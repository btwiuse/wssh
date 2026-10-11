package cafe

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/log/v2"
	"github.com/routercafe/routercafe/auth/agentkey"
	"github.com/routercafe/routercafe/auth/siws"
	"github.com/routercafe/routercafe/solana"
)

// Depositing.
//
// The money moves the way every other transaction in this repository moves:
// the session asks the agent it has been given for a signature, and nothing
// here holds a key. `ssh -A router.cafe` puts the client's own agent on the
// other end of a channel, so the private key never leaves the machine that
// owns it and a deposit is a signature request like any other.
//
// The chain is the authority on whether the money arrived. A deposit is
// credited when a signature the cluster confirms says the transfer landed, not
// when the agent returns a signed transaction - a signature is a statement
// about a transaction, and only the cluster can say whether it was included.

// DefaultRPC is the endpoint a deposit is sent to when nothing says otherwise.
const DefaultRPC = "https://api.mainnet-beta.solana.com"

// Treasury is where deposited SOL goes, and what a deposit is worth.
//
// SolPriceUSD is fixed per deposit rather than read from a price feed at the
// moment the money lands. That is a real simplification and it is deliberate:
// a price oracle is a second thing that can be wrong, and being wrong about it
// means either an account credited at a rate nobody agreed to or a deposit
// that cannot be honoured. The operator sets the rate their treasury will
// honour, and a session shows the rate it was credited at.
type Treasury struct {
	// Address is the account deposits are sent to.
	Address string

	// RPC is the JSON-RPC endpoint used for the blockhash, the broadcast and
	// the confirmation. Empty means DefaultRPC.
	RPC string

	// SolPriceUSD is what one SOL is worth, in micro-USD.
	SolPriceUSD MicroUSD

	// DryRun prices a deposit and reports what it would have done, without
	// asking for a signature, broadcasting anything, or moving a balance.
	// For walking the flow through before a treasury address exists, and for
	// a devnet; obviously not the setting for a public instance.
	DryRun bool

	// Now is the clock, for tests.
	Now func() time.Time
}

func (t Treasury) rpcURL() string {
	if strings.TrimSpace(t.RPC) != "" {
		return t.RPC
	}
	return DefaultRPC
}

func (t Treasury) clock() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Credits is what a deposit of this many lamports is worth, in micro-USD.
//
// Rounded down rather than to nearest. The rounding belongs to the operator
// and rounding down is the direction that cannot create a credit nobody paid
// for: the smallest possible difference is one micro-USD, which is a millionth
// of a dollar, and rounding the other way would make a rounding rule into a
// way to mint a little money out of many small deposits.
func (t Treasury) Credits(lamports uint64) MicroUSD {
	return MicroUSD(lamports) * t.SolPriceUSD / 1_000_000_000
}

// DepositReceipt is what a confirmed deposit produced.
type DepositReceipt struct {
	// Lamports is what arrived on chain.
	Lamports uint64

	// Credits is what it was worth, in micro-USD, at the rate the operator
	// set. This is the number credited, and the one the TUI shows.
	Credits MicroUSD

	// Signature is the transaction, so the person can look it up themselves
	// rather than taking this server's word for it. Empty on a dry run,
	// where nothing was signed or sent.
	Signature string

	// Pending is true when this was a dry run: the numbers are what would
	// have happened, and no balance changed.
	Pending bool
}

// Deposit builds, signs, sends and confirms a transfer from the caller's own
// account into the treasury, and credits the ledger once the cluster says it
// landed.
//
// from is the Solana account to take the money from, which is also the account
// credited: the signature comes from that same key, because a session may only
// ever move its own balance. sockPath is the agent socket the session was
// given, empty meaning $SSH_AUTH_SOCK.
//
// The order matters and is the whole of the safety here. The transaction names
// exactly two accounts, the source and the treasury; the signer is the
// source; and the returned transaction is checked against the signature and
// the fee payer before a single byte goes to the network. A deposit that would
// touch a third account is not one this function can express.
func Deposit(ctx context.Context, ledger *Ledger, treasury Treasury, from, sockPath string, lamports uint64) (DepositReceipt, error) {
	if err := ValidateAddress(from); err != nil {
		return DepositReceipt{}, fmt.Errorf("the account to pay from: %w", err)
	}
	if treasury.Address == "" {
		return DepositReceipt{}, errors.New("no treasury address is configured, so there is nowhere to send the deposit")
	}
	if err := ValidateAddress(treasury.Address); err != nil {
		return DepositReceipt{}, fmt.Errorf("the treasury address: %w", err)
	}
	if from == treasury.Address {
		// The System Program refuses a transfer whose source and
		// destination are the same account, and it charges the fee for the
		// attempt. Saying so here costs nothing and saves the fee.
		return DepositReceipt{}, errors.New(
			"that is the treasury's own address: a transfer to yourself is refused by the chain, and the fee is still charged")
	}
	if lamports == 0 {
		return DepositReceipt{}, errors.New("a deposit of nothing is not worth signing")
	}
	if sockPath == "" {
		return DepositReceipt{}, errors.New(
			"no agent: this session has no SSH_AUTH_SOCK, so nothing here can ask for a signature. " +
				"Connect with 'ssh -A router.cafe'")
	}

	// The fee is a few thousand lamports, and a transfer smaller than it
	// consumes the whole deposit before it moves anything. Better said up
	// front than discovered after a signature.
	const feeFloor = 10_000
	if lamports < feeFloor {
		return DepositReceipt{}, fmt.Errorf(
			"%s is below the ~%s network fee a transfer costs, so it would be spent without arriving",
			solText(lamports), solText(feeFloor))
	}

	// The instruction is built before anything else happens, so a dry run can
	// show what would have been sent - and so an amount that cannot be a
	// transfer is refused before a signature is asked for.
	//
	// NewTransfer names the destination; solana/build.go adds the fee payer as
	// the source, and the fee payer is the signer, which is the account
	// paying. So the transaction that comes out has exactly the two accounts
	// it should: from, and the treasury.
	instructions, err := solana.NewTransfer(solana.TransferInstruction{
		Lamports: lamports,
		To:       treasury.Address,
	})
	if err != nil {
		return DepositReceipt{}, err
	}
	if treasury.DryRun {
		log.Info("deposit dry run", "account", from, "lamports", lamports,
			"credits", treasury.Credits(lamports), "instructions", len(instructions))
		return DepositReceipt{
			Lamports: lamports,
			Credits:  treasury.Credits(lamports),
			Pending:  true,
		}, nil
	}

	blockhash, err := solana.LatestBlockhash(ctx, treasury.rpcURL())
	if err != nil {
		return DepositReceipt{}, fmt.Errorf("before signing: %w", err)
	}

	label := fmt.Sprintf("RouterCafe deposit: %s", solText(lamports))
	resp, err := solana.Ask(ctx, sockPath, agentkey.SolanaTxRequest{
		Blockhash:    blockhash,
		Label:        label,
		Signer:       from,
		Instructions: instructions,
	})
	if err != nil {
		return DepositReceipt{}, fmt.Errorf("asking for a signature: %w", err)
	}

	// Check the answer rather than trusting it. The agent is on the far side
	// of a connection this server does not control - it is the client's, and
	// in the browser case it is code in somebody else's page - so the bytes
	// that came back are inspected before they are broadcast. Both checks are
	// about the same thing: that what was signed is a transfer of this size
	// from this account to the treasury, and nothing else.
	if err := checkDeposit(resp.SignedTransaction, resp.Signature, from, treasury.Address, lamports); err != nil {
		return DepositReceipt{}, err
	}

	signature, err := solana.SendTransaction(ctx, treasury.rpcURL(), resp.SignedTransaction)
	if err != nil {
		return DepositReceipt{}, fmt.Errorf("sending the deposit: %w", err)
	}
	if err := solana.ConfirmTransaction(ctx, treasury.rpcURL(), signature); err != nil {
		// The broadcast succeeded and confirmation did not follow, which is
		// genuinely ambiguous: the money may well have arrived. Not crediting
		// is the safe half of that, because crediting on an unconfirmed
		// transfer is lending.
		return DepositReceipt{}, fmt.Errorf(
			"the deposit was broadcast as %s but has not confirmed yet, so nothing has been credited. "+
				"Check that signature before paying again: %w", signature, err)
	}

	credits := treasury.Credits(lamports)
	if err := ledger.Credit(from, credits); err != nil {
		// The money arrived and the ledger could not record it. That is the
		// one failure with a person on the wrong end of it, so it is said
		// out loud with the signature in the sentence: it is what an operator
		// needs to credit the account by hand, and losing it would leave
		// somebody's money in the treasury with no record of who it was for.
		log.Error("deposit confirmed but could not be credited",
			"account", from, "lamports", lamports, "credits", credits,
			"signature", signature, "error", err)
		return DepositReceipt{}, fmt.Errorf(
			"your %s arrived (signature %s) but the balance could not be recorded: %w. "+
				"Quote that signature and it can be credited by hand",
			solText(lamports), signature, err)
	}

	log.Info("deposit credited",
		"account", from, "lamports", lamports, "credits", credits, "signature", signature)
	return DepositReceipt{Lamports: lamports, Credits: credits, Signature: signature}, nil
}

// checkDeposit reads the signed transaction back and confirms it is the
// transfer that was asked for.
//
// Four things are checked, and each of them is a way the answer could differ
// from the request in a way that costs somebody money:
//
//   - the signature verifies against the transaction message, so what comes
//     back is what was signed rather than a claim about what was signed;
//   - the fee payer is the account being debited, read out of the signed
//     bytes rather than out of the request;
//   - the only writable account the message names, besides the source, is the
//     treasury, so the transaction cannot be moving somebody else's balance;
//   - the transfer carries this many lamports.
//
// Anything that fails is a refusal, and nothing is broadcast.
func checkDeposit(signed []byte, signature []byte, from, treasuryAddress string, lamports uint64) error {
	if len(signed) == 0 {
		return errors.New("the agent returned no signed transaction")
	}
	if len(signature) == 0 {
		return errors.New("the agent returned no signature")
	}

	// The signature first, against the message: what came back is a real
	// signature by the paying account over these exact bytes, or it is not
	// used at all.
	payerKey, err := siws.Base58Decode(from)
	if err != nil {
		return fmt.Errorf("the paying account is not an address: %w", err)
	}
	if err := solana.VerifySigned(signed, ed25519.PublicKey(payerKey)); err != nil {
		return fmt.Errorf("the signed transaction does not check out: %w", err)
	}

	payer, err := solana.FeePayer(signed)
	if err != nil {
		return fmt.Errorf("the signed transaction names no fee payer: %w", err)
	}
	if payer != from {
		// The routing rule this repository already follows: a named payer
		// has to be the one that signed. Here it is also the account whose
		// balance moves, so a mismatch is a transaction charging the wrong
		// person's account.
		return fmt.Errorf(
			"the transaction was paid by %s, not by %s: it would move an account this session does not own",
			payer, from)
	}

	message, err := solana.DecodeSigned(signed)
	if err != nil {
		return fmt.Errorf("the signed transaction could not be read back: %w", err)
	}
	return checkTransfer(message, from, treasuryAddress, lamports)
}

// checkTransfer confirms a decoded message is the deposit that was asked for.
//
// The rules, and what each one stops:
//
//   - one instruction, and it is a System Program transfer. A deposit is the
//     only thing this function signs, so anything else in the message is a
//     transaction doing something nobody read.
//   - the writable accounts are the source and the treasury, and no others.
//     Writable is the flag that means an account can change, and a message
//     naming a third one can move somebody else's money even if every
//     instruction is a transfer.
//   - the transfer carries this many lamports.
//
// Checked here rather than at the wallet because the wallet is not the only
// thing that can be on the far end of that agent socket: `ssh -A` puts a
// client's own ssh-agent there, and that agent signs whatever it is handed.
func checkTransfer(msg solana.Message, from, treasuryAddress string, lamports uint64) error {
	if msg.LookupTables > 0 {
		return fmt.Errorf("the transaction uses %d address lookup tables, which this deposit does not build", msg.LookupTables)
	}
	if len(msg.Instructions) != 1 {
		return fmt.Errorf("the transaction carries %d instructions; a deposit is exactly one transfer", len(msg.Instructions))
	}
	ix := msg.Instructions[0]
	if ix.ProgramID != solana.SystemProgramID {
		return fmt.Errorf("the transaction calls %s; a deposit is a System Program transfer", ix.ProgramID)
	}

	for _, acct := range msg.Accounts {
		if acct.Address != from && acct.Address != treasuryAddress && acct.Writable {
			return fmt.Errorf(
				"the transaction can change %s, which is neither the account paying (%s) nor the treasury (%s)",
				acct.Address, from, treasuryAddress)
		}
	}

	// A System transfer takes [source, destination] once it is in a message.
	// solana/build.go inserts the payer as the source because the request is
	// written before the signer is known, so a decoded transfer always names
	// two accounts and the first has to be the account being debited.
	if len(ix.Accounts) != 2 {
		return fmt.Errorf("the transfer names %d accounts; a transfer names its source and its destination", len(ix.Accounts))
	}
	if ix.Accounts[0] != from {
		return fmt.Errorf("the transfer takes the money from %s, not from %s", ix.Accounts[0], from)
	}
	if ix.Accounts[1] != treasuryAddress {
		return fmt.Errorf("the transfer sends to %s, not to the treasury %s", ix.Accounts[1], treasuryAddress)
	}

	got, err := transferAmount(ix.Data)
	if err != nil {
		return err
	}
	if got != lamports {
		return fmt.Errorf("the transfer moves %s, not the %s that was asked for", solText(got), solText(lamports))
	}
	return nil
}

// transferAmount reads the amount out of a System Program transfer.
//
// The layout is twelve fixed bytes - a four-byte discriminant of two, then
// eight little-endian of lamports - and the length is checked rather than
// assumed, because a longer data field is a transaction doing something else
// with the same program.
func transferAmount(data []byte) (uint64, error) {
	if len(data) != 12 {
		return 0, fmt.Errorf("the transfer carries %d bytes of data; a transfer is 12", len(data))
	}
	if data[0] != 2 {
		return 0, fmt.Errorf("the transfer's discriminant is %d, not 2, so it is not a transfer", data[0])
	}
	var amount uint64
	for i := 0; i < 8; i++ {
		amount |= uint64(data[4+i]) << (8 * i)
	}
	return amount, nil
}

// solText is an amount in lamports written as SOL, for the sentences a person
// reads. The arithmetic is on integers and the printing is the only place a
// decimal point appears, so no rounding decision lives in the middle.
func solText(lamports uint64) string {
	const per = 1_000_000_000
	whole := lamports / per
	frac := lamports % per
	if frac == 0 {
		return fmt.Sprintf("%d SOL", whole)
	}
	// Nine digits and no truncation: nine is exactly one lamport, and cutting
	// the tail off would print a one-lamport amount as "0.000000 SOL", which
	// is a different number and the one the reader would take away.
	digits := strings.TrimRight(fmt.Sprintf("%09d", frac), "0")
	return fmt.Sprintf("%d.%s SOL", whole, digits)
}
