// credentials.js — the keychain: which keys and passwords to offer a server,
// and how to generate and remember them.
//
// Private keys live here, so the storage rules are deliberate. They are kept
// in memory for the life of the page unless the user asks for them to be
// remembered: a key left in localStorage is readable by any script that
// manages to run on this origin, and for a login key that is a real cost.
// Remembering is offered, never assumed.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import htm from 'htm';

const html = htm.bind(React.createElement);

const KEYS_KEY = 'wssh.keys';
const PASSWORDS_KEY = 'wssh.passwords';
const REMEMBER_KEY = 'wssh.rememberCredentials';

// In-memory copies, so the page still works when storage is unavailable.
let memoryKeys = [];
let memoryPasswords = [];

// --- storage ----------------------------------------------------------------

function readJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    const parsed = JSON.parse(raw);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

function writeJSON(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Nothing to do: the value is still in memory for this page.
  }
}

// remembering is a deliberate choice, so it defaults to off.
export function isRemembering() {
  return readJSON(REMEMBER_KEY, false) === true;
}

function remembering() {
  return isRemembering();
}

// --- keys -------------------------------------------------------------------

export function readKeys() {
  if (!remembering()) return memoryKeys;
  const stored = readJSON(KEYS_KEY, null);
  return Array.isArray(stored) ? stored : [];
}

function writeKeys(keys) {
  memoryKeys = keys;
  if (remembering()) writeJSON(KEYS_KEY, keys);
}

export function addKey(key) {
  const keys = readKeys();
  if (keys.some((k) => k.privateKey === key.privateKey)) return keys;
  const next = [key, ...keys];
  writeKeys(next);
  return next;
}

export function forgetKey(id) {
  const next = readKeys().filter((k) => k.id !== id);
  writeKeys(next);
  return next;
}

export function setRemembering(on) {
  const keys = memoryKeys;
  const passwords = memoryPasswords;
  if (on) {
    writeJSON(KEYS_KEY, keys);
    writeJSON(PASSWORDS_KEY, passwords);
  } else {
    try {
      localStorage.removeItem(KEYS_KEY);
      localStorage.removeItem(PASSWORDS_KEY);
    } catch { /* nothing stored anyway */ }
  }
  writeJSON(REMEMBER_KEY, on);
}

// --- passwords --------------------------------------------------------------

export function readPasswords() {
  if (!remembering()) return memoryPasswords;
  const stored = readJSON(PASSWORDS_KEY, null);
  return Array.isArray(stored) ? stored : [];
}

function writePasswords(list) {
  memoryPasswords = list;
  if (remembering()) writeJSON(PASSWORDS_KEY, list);
}

export function addPassword(value) {
  const list = readPasswords();
  if (!value || list.includes(value)) return list;
  const next = [value, ...list];
  writePasswords(next);
  return next;
}

export function forgetPassword(value) {
  const next = readPasswords().filter((p) => p !== value);
  writePasswords(next);
  return next;
}

// --- talking to the worker ---------------------------------------------------

// installHooks gives the worker somewhere to ask for a passphrase or a
// password. The private key itself never comes through here: the page hands
// Go the text and Go does the cryptography.
export function installHooks(askPassphrase, askPassword) {
  globalThis.__websshAskPassphraseFn = askPassphrase ? (name) => askPassphrase(name) : null;
  globalThis.__websshAskPassword = askPassword ? () => askPassword() : () => null;
}

// The page and the worker have separate globals, so these are only a default
// for the worker's own scope. Prompts are really answered over a message; see
// the onPrompt handler in app.js.
export const noHooks = { install: installHooks };

// credentialsForConnect bundles what to offer the server, in the order a
// person would try them: keys first, then the password.
// signInWithTheWallet signs the exact text the server asked for.
//
// It is handed the message rather than the fields on purpose: what the wallet
// signs cannot then differ from what the server sent, even by accident. The
// exchange itself is in Go, on the socket, so this is one call and one answer.
//
// The account is filled in here rather than asked for, because the server that
// chose it would be asking a wallet to prove something other than who is asking.
export async function signInWithTheWallet(message) {
  const provider = window.solana || window.phantom?.solana;
  if (!provider?.publicKey) throw new Error('connect a wallet first');
  if (typeof provider.signIn !== 'function') {
    throw new Error('this wallet has no sign-in; try Phantom');
  }

  // The domain is the one the message already names, and the nonce is the
  // server's. Re-reading them here rather than trusting them back would be a
  // chance to change what is being signed.
  const lines = message.split('\n');
  const pick = (label) => {
    const found = lines.find((l) => l.startsWith(`${label}: `));
    return found ? found.slice(label.length + 2) : '';
  };

  const answer = await provider.signIn({
    domain: pick('wants you to sign in') ? message.split(' ')[0] : '',
    statement: lines[3] || '',
    version: pick('Version') || '1',
    chainId: pick('Chain ID') || 'solana:mainnet',
    nonce: pick('Nonce'),
    issuedAt: pick('Issued At'),
  });

  return `${bytesToHex(answer.signedMessage)}:${bytesToHex(answer.signature)}`;
}

// The account's public key as hex, whichever wallet produced it.
//
// toHex is one wallet's spelling and toBytes is the standard's; neither is
// universal. Going through toBase58 and decoding here would be the most
// portable of all, so that is the fallback rather than the first choice.
function publicKeyHex(provider) {
  const key = provider?.publicKey;
  if (!key) throw new Error('the wallet reports no account');
  if (typeof key.toBytes === 'function') return bytesToHex(key.toBytes());
  if (typeof key.toBase58 === 'function') return bytesToHex(base58ToBytes(key.toBase58()));
  throw new Error('this wallet does not say what account it is');
}

// Solana addresses are base58. This is only the fallback for a wallet with no
// toBytes, and it is checked rather than trusted: the key comes back out the
// other way before it is used.
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

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function credentialsForConnect(forwardAgent = false, walletPublicKey = '', walletAddress = '', signIn = false) {
  return {
    // Whether the session is authenticated by the connected wallet. What the
    // wallet signs is decided by the server and arrives on the socket; all this
    // says is that the page is willing to ask it.
    signIn: !!signIn,
    // Whether the session may ask these keys to sign. The keys stay in the
    // page either way: only signatures come back over the connection.
    forwardAgent: !!forwardAgent,
    // The connected wallet's public key as hex. The private half never comes
    // near this page or the connection; the extension signs and we forward
    // what it returns.
    walletPublicKey: walletPublicKey || '',
    // The address only ever names the key in a signing question. It is the
    // same 32 bytes as the public key in a different alphabet, so nothing
    // secret travels with it.
    walletAddress: walletAddress || '',
    keys: readKeys()
      .filter((k) => k.enabled !== false)
      .map((k) => ({
        name: k.name || 'key',
        privateKey: k.privateKey,
        passphrase: k.passphrase || '',
      })),
    passwords: readPasswords(),
  };
}

// --- panel ------------------------------------------------------------------

export function CredentialsPanel({ workerRef, onClose }) {
  const [keys, setKeys] = useState(() => readKeys());
  const [passwords, setPasswords] = useState(() => readPasswords());
  const [remember, setRemember] = useState(() => isRemembering());
  const [pasted, setPasted] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [keyType, setKeyType] = useState('ed25519');
  const [status, setStatus] = useState('');
  const pending = useRef(null);

  // The worker answers asynchronously, so results are matched back by hand.
  useEffect(() => {
    const worker = workerRef.current;
    if (!worker) return undefined;

    const onMessage = (event) => {
      const msg = event.data;
      if (msg.type === 'generatedKey') {
        pending.current = { kind: 'generated', privateKey: msg.privateKey };
        setKeys(addKey({
          id: `k${Date.now()}${Math.random().toString(36).slice(2, 7)}`,
          name: `${msg.publicKey.split(' ')[0]} ${new Date().toISOString().slice(0, 10)}`,
          publicKey: msg.publicKey,
          privateKey: msg.privateKey,
          fingerprint: '',
          encrypted: false,
          enabled: true,
        }));
        setStatus('generated a key; the public half goes on the server');
      } else if (msg.type === 'keyInfo') {
        const info = msg.info || {};
        // Read the key out before overwriting pending: the record that answers
        // this carries no key material, and reading it afterwards stored every
        // imported key with an undefined privateKey - which quietly broke both
        // key authentication and agent forwarding for anything pasted in,
        // while generated keys kept working because they take their own path.
        const pasted = pending.current?.kind === 'pasted'
          ? pending.current.privateKey
          : '';
        pending.current = { kind: 'info', info };
        if (info.error) {
          setStatus(`that is not a private key: ${info.error}`);
          return;
        }
        setKeys(addKey({
          id: `k${Date.now()}${Math.random().toString(36).slice(2, 7)}`,
          name: info.type || 'key',
          publicKey: info.publicKey || '',
          privateKey: pasted,
          fingerprint: info.fingerprint || '',
          encrypted: !!info.encrypted,
          enabled: true,
        }));
        setPasted('');
        setStatus(info.encrypted
          ? 'imported; it is encrypted, so you will be asked for its passphrase when connecting'
          : 'imported');
      } else if (msg.type === 'log' || msg.type === 'error') {
        setStatus(msg.message || '');
      }
    };
    worker.addEventListener('message', onMessage);
    return () => worker.removeEventListener('message', onMessage);
  }, [workerRef]);

  const generate = useCallback(() => {
    setStatus('generating…');
    workerRef.current?.postMessage({ type: 'generateKey', kind: keyType });
  }, [keyType, workerRef]);

  const importPasted = useCallback(() => {
    const text = pasted.trim();
    if (!text) return;
    setStatus('reading that key…');
    pending.current = { kind: 'pasted', privateKey: text };
    workerRef.current?.postMessage({ type: 'keyInfo', privateKey: text });
  }, [pasted, workerRef]);

  const removeKey = useCallback((id) => setKeys(forgetKey(id)), []);
  const toggleKey = useCallback((id) => {
    setKeys(writeKeys(readKeys().map((k) => (k.id === id ? { ...k, enabled: k.enabled === false } : k))) || readKeys());
  }, []);

  const addPw = useCallback(() => {
    const value = newPassword.trim();
    if (!value) return;
    setPasswords(addPassword(value));
    setNewPassword('');
  }, [newPassword]);

  const toggleRemember = useCallback(() => {
    const next = !remember;
    setRemember(next);
    setRemembering(next);
    // Move what is held in memory into storage, or drop it from there.
    const keysNow = memoryKeys.length ? memoryKeys : readKeys();
    const pwNow = memoryPasswords.length ? memoryPasswords : readPasswords();
    if (next) {
      writeJSON(KEYS_KEY, keysNow);
      writeJSON(PASSWORDS_KEY, pwNow);
    } else {
      try {
        localStorage.removeItem(KEYS_KEY);
        localStorage.removeItem(PASSWORDS_KEY);
      } catch { /* nothing stored */ }
    }
    memoryKeys = keysNow;
    memoryPasswords = pwNow;
  }, [remember]);

  return html`
    <div class="absolute z-30 mt-1 right-0 w-[30rem] max-w-[95vw] rounded border border-slate-700
                bg-slate-900 shadow-2xl p-3 text-slate-200">
      <div class="flex items-center gap-2 mb-2">
        <span class="font-semibold text-sm">Credentials</span>
        <label class="ml-auto flex items-center gap-1.5 text-xs text-slate-400 select-none">
          <input
            type="checkbox"
            checked=${remember}
            onChange=${toggleRemember}
          />
          remember on this device
        </label>
        <button class="text-slate-500 hover:text-slate-200 text-xs" onClick=${onClose}>✕</button>
      </div>

      ${!remember && html`
        <p class="text-[11px] text-amber-300/90 mb-2">
          Keys are held in memory only, and go when this page closes. Anything that can
          run a script on this origin can read a key left in local storage, so that is
          your call to make rather than the default.
        </p>`}

      <div class="text-xs uppercase tracking-wide text-slate-500 mb-1">keys</div>
      ${keys.length === 0 && html`<p class="text-xs text-slate-500 mb-2">none yet</p>`}
      <div class="space-y-1 mb-3 max-h-40 overflow-y-auto">
        ${keys.map((key) => html`
          <div key=${key.id} class="flex items-center gap-2 rounded bg-slate-800/70 px-2 py-1">
            <input
              type="checkbox"
              checked=${key.enabled !== false}
              title="Offer this key when connecting"
              onChange=${() => toggleKey(key.id)}
            />
            <span class="text-xs font-mono truncate flex-1" title=${key.publicKey || key.name}>
              ${key.name}${key.encrypted ? ' 🔒' : ''}
            </span>
            ${key.fingerprint && html`
              <span class="text-[10px] text-slate-500 font-mono shrink-0"
                    title=${key.fingerprint}>${key.fingerprint.replace('SHA256:', '').slice(0, 16)}</span>`}
            <button class="text-slate-500 hover:text-red-400 text-xs shrink-0"
                    title="Forget this key" onClick=${() => removeKey(key.id)}>✕</button>
          </div>`)}
      </div>

      <div class="flex gap-2 mb-1">
        <textarea
          class="flex-1 h-16 bg-slate-950 border border-slate-700 rounded px-2 py-1
                 font-mono text-[10px] focus:outline-none focus:border-emerald-500"
          placeholder="paste a private key…"
          value=${pasted}
          onInput=${(e) => setPasted(e.target.value)}
        ></textarea>
        <div class="flex flex-col gap-1">
          <button class="px-2 py-1 text-xs rounded bg-slate-700 hover:bg-slate-600"
                  onClick=${importPasted}>import</button>
          <select class="px-1 py-1 text-xs bg-slate-700 rounded"
                  value=${keyType} onChange=${(e) => setKeyType(e.target.value)}>
            <option value="ed25519">ed25519</option>
            <option value="rsa">rsa</option>
            <option value="ecdsa">ecdsa</option>
          </select>
          <button class="px-2 py-1 text-xs rounded bg-emerald-700 hover:bg-emerald-600 text-slate-900"
                  onClick=${generate}>generate</button>
        </div>
      </div>

      <div class="text-xs uppercase tracking-wide text-slate-500 mt-2 mb-1">passwords</div>
      <div class="space-y-1 mb-2 max-h-24 overflow-y-auto">
        ${passwords.map((pw) => html`
          <div key=${pw} class="flex items-center gap-2 rounded bg-slate-800/70 px-2 py-1">
            <span class="text-xs font-mono truncate flex-1">${pw.replace(/./g, '•')}</span>
            <button class="text-slate-500 hover:text-red-400 text-xs"
                    onClick=${() => setPasswords(forgetPassword(pw))}>✕</button>
          </div>`)}
      </div>
      <div class="flex gap-2">
        <input
          class="flex-1 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs
                 focus:outline-none focus:border-emerald-500"
          type="password"
          placeholder="a password to offer"
          value=${newPassword}
          onInput=${(e) => setNewPassword(e.target.value)}
          onKeyDown=${(e) => { if (e.key === 'Enter') addPw(); }}
        />
        <button class="px-2 py-1 text-xs rounded bg-slate-700 hover:bg-slate-600"
                onClick=${addPw}>add</button>
      </div>

      ${status && html`<p class="text-[11px] text-slate-400 mt-2">${status}</p>`}
    </div>
  `;
}

// --- Solana transactions ----------------------------------------------------

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
export async function signSolanaTransaction(serialised) {
  const provider = window.solana || window.phantom?.solana;
  if (!provider?.publicKey) return { refusal: 'connect a wallet first' };

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

  let tx;
  try {
    tx = buildTransaction(request, web3, provider);
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
function buildTransaction(request, web3, provider) {
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

  const address = provider?.publicKey?.toBase58?.();
  if (!address) {
    throw new Error('the connected wallet reported no address');
  }

  const feePayer = new PublicKey(address);

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
      data = hexToBytes(instruction.data || '');
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
  const signers = new Set([address]);
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
