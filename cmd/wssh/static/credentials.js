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
export function credentialsForConnect(forwardAgent = false) {
  return {
    // Whether the session may ask these keys to sign. The keys stay in the
    // page either way: only signatures come back over the connection.
    forwardAgent: !!forwardAgent,
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