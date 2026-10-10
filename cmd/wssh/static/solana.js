// solana.js — building and describing a Solana transaction for the wallet to
// sign.
//
// It is its own module because none of this needs React, and the selftest
// imports it directly: the point of that test is to check the page's real
// builder against the server's real reader, and a copy of either would test
// nothing.

// Building and signing a Solana transaction.
//
// The library does the serialising, on this side, for two reasons: it is the
// one that tracks Solana's transaction format as it changes, and the wallet is
// here so this is where the transaction can be built at all. Nothing about a
// transaction is assembled by hand.
//
// What this function does *not* do is decide anything. It builds what was
// asked for, describes it in words, and hands it to the wallet: the person
// approving is the one who decides, and this only has to make sure they are
// approving something legible rather than something they cannot read.
//
// A refusal is returned as a refusal rather than thrown, because the caller
// half is a session and the reason is the most useful thing it will be told.
// buildOnly says the caller will sign with a key of its own, so the
// transaction goes back unsigned instead of being put to a wallet.
export async function signSolanaTransaction(serialised, buildOnly = false) {
  const provider = window.solana || window.phantom?.solana;
  if (buildOnly && !provider?.publicKey) {
    // Nothing to sign with here, which is fine: the caller signs. The library
    // is still needed, because the serialisation is the part that has to be
    // right.
  } else if (!provider?.publicKey) {
    return { refusal: 'connect a wallet first' };
  }

  // What arrives is the JSON Go marshalled, not an object. Treating the string
  // as the request makes every field missing, and the first symptom of that is
  // an empty instruction list rather than anything mentioning the parse.
  let request;
  try {
    request = JSON.parse(serialised);
  } catch (err) {
    return { refusal: `the request was not readable JSON: ${err.message}` };
  }
  if (typeof provider.signTransaction !== 'function') {
    return { refusal: 'this wallet cannot sign transactions' };
  }

  // A refusal comes back as a string, so a failure to load reaches the person
  // in the session with its reason rather than as a shrug.
  const web3 = await loadWeb3();
  if (typeof web3 === 'string') return { refusal: web3 };
  if (!web3?.Transaction) {
    return { refusal: `${WEB3_URL} loaded but has no Transaction on it` };
  }

  // Without a wallet there is no fee payer to name, so the session's own key
  // pays. It is the key that signed in, so it is the one the transaction has
  // to name as well.
  const payer = provider?.publicKey?.toBase58?.() || request.payer;
  if (!payer) {
    return { refusal: 'no fee payer: connect a wallet, or say which key to pay with' };
  }

  let tx;
  try {
    tx = buildTransaction(request, web3, provider, payer);
  } catch (err) {
    return { refusal: `the transaction could not be built: ${err.message}` };
  }

  // A transaction that arrives at the wallet empty would be approved with
  // nothing on screen and signed as a fee-only transaction, which is not what
  // was asked for. The count is compared rather than trusted: losing an
  // instruction in the library is silent, and "0 instructions" is exactly the
  // thing a person reads past.
  const described = describeTransaction(tx, request.label);
  const wanted = request.instructions.length;
  const shown = compiledInstructions(tx).length;
  if (shown !== wanted) {
    return {
      refusal: `the transaction lost instructions on the way to the wallet: `
        + `${wanted} were asked for, ${shown} would have been signed`,
    };
  }

  if (!window.confirm(described)) {
    return { refusal: 'refused' };
  }

  // The caller signs with a key it holds, so hand back the built transaction
  // as it stands, with its signature slots still empty.
  if (buildOnly) {
    lastBuilt = tx.message.compiledInstructions.map((ix) => ix.data);
    return { unsigned: bytesToHex(tx.serialize()) };
  }

  let signed;
  try {
    signed = await provider.signTransaction(tx);
  } catch (err) {
    // The wallet's own wording is the useful part here: it is what tells
    // someone apart from having closed the popup on purpose.
    return { refusal: `the wallet did not sign: ${err?.message || err}` };
  }

  // A versioned transaction carries its signatures in a list, so the one this
  // wallet just made is the first. Reading .signature off it finds nothing.
  const signature = Array.isArray(signed?.signatures)
    ? signed.signatures[0]
    : signed?.signature;
  if (!signature) {
    return { refusal: 'the wallet returned no signature in the transaction it signed' };
  }

  let serialized;
  try {
    serialized = signed.serialize();
  } catch (err) {
    return { refusal: `the signed transaction could not be read back: ${err?.message || err}` };
  }

  return {
    publicKey: publicKeyHex(provider),
    signature: bytesToHex(signature),
    signedTransaction: bytesToHex(serialized),
  };
}

// Build checks each input as it goes and says which one was wrong.
//
// A versioned transaction is what a current wallet expects. The older
// Transaction type is still built as a fallback, because a wallet that wants
// it will say so more clearly than "Expected String" does.
function buildTransaction(request, web3, provider, payer) {
  const {
    PublicKey, TransactionInstruction, VersionedTransaction, TransactionMessage,
  } = web3;

  const key = (what, value) => {
    if (!value || typeof value !== 'string') {
      throw new Error(`the request has no ${what}`);
    }
    try {
      return new PublicKey(value);
    } catch (err) {
      throw new Error(`the ${what} "${value}" is not a Solana address: ${err?.message || err}`);
    }
  };

  // A blockhash stays a string all the way through. The serialiser base58
  // decodes it directly, so handing it a PublicKey makes it throw "Expected
  // String" from inside the library - which arrives looking like the wallet
  // refusing, because that is where the failure surfaces. It is checked as an
  // address so a bad one is named here rather than deep in serialise().
  const blockhash = request?.blockhash;
  if (typeof blockhash !== 'string' || !blockhash) {
    throw new Error('the request has no blockhash');
  }
  try {
    key('blockhash', blockhash);
  } catch (err) {
    throw err;
  }

  if (!request || !Array.isArray(request.instructions) || request.instructions.length === 0) {
    throw new Error('the request carries no instructions');
  }

  const feePayer = new PublicKey(payer);

  const instructions = [];
  for (const [i, instruction] of request.instructions.entries()) {
    if (!instruction?.accounts?.length) {
      throw new Error(`instruction ${i} names no accounts`);
    }

    let programId;
    try {
      programId = key(`program for instruction ${i}`, instruction.programId);
    } catch (err) {
      throw err;
    }

    const keys = [];
    for (const [j, account] of instruction.accounts.entries()) {
      try {
        keys.push({
          pubkey: key(`account ${j} of instruction ${i}`, account.address),
          isSigner: !!account.isSigner,
          isWritable: !!account.isWritable,
        });
      } catch (err) {
        throw err;
      }
    }

    let data;
    try {
      // Base58, because that is what the field carries. Read as hex it came
      // out as eight bytes of nonsense instead of twelve - and a signature over
      // nonsense verifies just as well as one over a transfer.
      data = base58ToBytes(instruction.data || '');
    } catch (err) {
      throw new Error(`instruction ${i} has data that is not hex: ${err?.message || err}`);
    }

    try {
      instructions.push(new TransactionInstruction({ programId, keys, data }));
    } catch (err) {
      throw new Error(`instruction ${i} could not be added: ${err?.message || err}`);
    }
  }

  if (!VersionedTransaction || !TransactionMessage) {
    throw new Error('this build of the Solana library cannot make a versioned transaction');
  }

  let message;
  try {
    message = new TransactionMessage({
      payerKey: feePayer,
      recentBlockhash: blockhash,
      instructions,
    });
  } catch (err) {
    throw new Error(`the transaction message could not be built: ${err?.message || err}`);
  }

  // The wallet takes a VersionedMessage, which is the serialised form, not the
  // friendly TransactionMessage. Handing it the latter is why the first attempt
  // came back as a version whose internals could not be read: the constructor
  // looks for a signature count the friendly form does not carry. The library
  // has the conversion.
  let compiled;
  try {
    compiled = message.compileToV0Message();
  } catch (err) {
    throw new Error(`the message could not be compiled: ${err?.message || err}`);
  }

  // The count of signature slots is still given rather than left to the
  // default, which is cheap and means the library is not asked to work it out
  // from a form it has already been shown not to handle.
  const signers = new Set([payer]);
  for (const ix of instructions) {
    for (const key of ix.keys) {
      if (key.isSigner) signers.add(key.pubkey.toBase58());
    }
  }

  try {
    return new VersionedTransaction(
      compiled,
      new Array(signers.size).fill(new Uint8Array(64)),
    );
  } catch (err) {
    throw new Error(`the transaction could not be assembled: ${err?.message || err}`);
  }
}

// What the person approving gets to see.
//
// It reads the compiled message rather than the objects it was built from,
// because that is what the signed transaction carries: addresses and data as
// base58 strings with indices instead of PublicKey instances. Reading the
// pre-compilation form meant reaching for .instructions on something that does
// not have them.
//
// Every account is named. A transaction shown as an opaque blob is a
// transaction approved blindly, and this is the moment where that matters.
function describeTransaction(tx, label) {
  const message = tx?.message;
  if (!message) {
    return 'A session wants you to sign a Solana transaction, but it could not be read back for review.';
  }

  const keys = message.staticAccountKeys || [];
  const header = message.header || {};
  const signerCount = header.numRequiredSignatures ?? 0;
  const instructions = compiledInstructions(tx);
  const lines = [];

  lines.push(label ? String(label) : 'A session wants to sign a Solana transaction.');
  lines.push('');
  lines.push(`blockhash: ${message.recentBlockhash || 'unknown'}`);
  lines.push(`${signerCount} signature(s) required`);
  lines.push(`${instructions.length} instruction(s):`);

  for (const [i, ix] of instructions.entries()) {
    lines.push('');
    lines.push(`  ${i + 1}. program ${keyName(keys, ix.programIdIndex)}`);
    const accounts = ix.accountKeyIndexes || [];
    if (!accounts.length) {
      lines.push('     (no accounts)');
    }
    for (const index of accounts) {
      const role = index < signerCount ? 'signs, ' : '';
      lines.push(`     ${role}${keyName(keys, index)}`);
    }
    lines.push(`     data ${bytesToHex(ix.data || [])}`);
  }

  lines.push('');
  lines.push('Signing does not send anything. The transaction has to be broadcast separately.');
  return lines.join('\n');
}

// A compiled message calls them compiledInstructions. The friendly form calls
// them instructions, so both are read: which one is present depends on how far
// along the transaction is, and reading only the other is what made an intact
// transaction look empty.
function compiledInstructions(tx) {
  const message = tx?.message;
  if (!message) return [];
  if (Array.isArray(message.compiledInstructions)) return message.compiledInstructions;
  if (Array.isArray(message.instructions)) return message.instructions;
  return [];
}

// An account can be named by index into the key list, or directly. Anything
// else is shown as itself rather than guessed at, since this is the text
// somebody is being asked to approve.
function keyName(keys, index) {
  if (typeof index === 'string') return index;
  const found = keys[index];
  if (typeof found === 'string') return found;
  // The compiled form keeps PublicKey objects rather than base58 text.
  if (found && typeof found.toBase58 === 'function') return found.toBase58();
  return `#${index}`;
}

// The library is loaded on first use rather than up front, so a session that
// never signs a transaction never pays for it.
//
// It comes from esm.sh rather than straight from the package, and that is not
// cosmetic. The published browser ESM build imports Node's "buffer", which a
// page with no bundler cannot resolve: the failure is a bare
// "Failed to resolve module specifier", which says nothing about which file was
// at fault. esm.sh resolves those to real browser packages, so what arrives
// actually runs.
const WEB3_URL = 'https://esm.sh/@solana/web3.js@3.0.2';

// What the last built transaction's instruction data actually was, so a
// mismatch with what comes back says which side lost the bytes.
let lastBuilt = null;
export function lastBuiltData() {
  return lastBuilt;
}

let web3Promise = null;

function loadWeb3() {
  if (web3Promise) return web3Promise;

  // Anything already on the page is good enough, and costs nothing: a page
  // that ships its own copy should not fetch a second one.
  if (window.solanaWeb3) {
    web3Promise = Promise.resolve(window.solanaWeb3);
    return web3Promise;
  }

  web3Promise = import(WEB3_URL).then(
    (mod) => mod?.default || mod,
    (err) => `could not load ${WEB3_URL}: ${err?.message || err}`,
  );
  return web3Promise;
}


function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function base58ToBytes(text) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const char of text) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error(`"${char}" is not in the base58 alphabet`);
    n = n * 58n + BigInt(digit);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.substr(i * 2, 2), 16);

  let leading = 0;
  for (const b of text) { if (b !== alphabet[0]) break; leading += 1; }
  const padded = new Uint8Array(leading + out.length);
  padded.set(out, leading);
  return padded;
}

function publicKeyHex(provider) {
  const key = provider?.publicKey;
  if (!key) throw new Error('the wallet reports no account');
  if (typeof key.toBytes === 'function') return bytesToHex(key.toBytes());
  if (typeof key.toBase58 === 'function') return bytesToHex(base58ToBytes(key.toBase58()));
  throw new Error('this wallet does not say what account it is');
}


/** Bytes as lower-case hex. Lives here because the transaction half needs it and
 *  the keychain needs it, and a helper that exists twice is one that eventually
 *  gets fixed once. */
export function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Start fetching the library now, without waiting for a transaction to ask.
 *
 * It comes off a CDN and its dependency tree is large enough that a cold
 * fetch runs for several seconds - long enough for a caller waiting on a
 * signature to give up first. Doing it while nothing depends on it turns the
 * one slow moment into a warm one.
 */
export function warmUp() {
  return loadWeb3();
}

/** Base58 to bytes. The selftest needs to read a signed transaction back, and
 *  the decoder that understands one already exists. */
export function base58Decode(text) {
  return base58ToBytes(text);
}
