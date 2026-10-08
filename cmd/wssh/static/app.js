// app.js — the terminal UI.
//
// No bundler: React and htm come from esm.sh via the import map in
// index.html, and xterm.js is a plain global from jsDelivr.

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import htm from 'htm';

const html = htm.bind(React.createElement);

// localStorage throws in more situations than people expect: Safari private
// browsing, blocked site data, some third-party storage policies. A terminal
// that refuses to render because it could not remember a text field is a bad
// trade, so every access goes through here and quietly falls back to memory
// for the life of the page.
const memoryStore = new Map();

const store = {
  get(key) {
    try {
      const value = localStorage.getItem(key);
      if (value !== null) return value;
    } catch {
      /* storage unavailable; fall through to memory */
    }
    return memoryStore.get(key);
  },
  set(key, value) {
    memoryStore.set(key, value);
    try {
      localStorage.setItem(key, value);
    } catch {
      /* remembered for this page only */
    }
  },
  getList(key) {
    const raw = store.get(key);
    if (raw === undefined) return [];
    try {
      const list = JSON.parse(raw);
      return Array.isArray(list) ? list.filter((s) => typeof s === 'string' && s) : [];
    } catch {
      return [];
    }
  },
  setList(key, list) {
    store.set(key, JSON.stringify(list));
  },
};

// Endpoints the user has actually connected to, most recent first. Loaded
// once: it is a list, not a single value, so keeping it in a module variable
// also means it survives storage being unavailable.
const ENDPOINTS_KEY = 'wssh.endpoints';
let savedEndpoints = store.getList(ENDPOINTS_KEY);

function rememberEndpoint(url) {
  const value = url.trim();
  if (!value) return;
  // Move to the front rather than adding a duplicate: the list is a recency
  // order, and a second copy of the same address helps nobody.
  savedEndpoints = [value, ...savedEndpoints.filter((e) => e !== value)].slice(0, 25);
  store.setList(ENDPOINTS_KEY, savedEndpoints);
}

function forgetEndpoint(value) {
  savedEndpoints = savedEndpoints.filter((e) => e !== value);
  store.setList(ENDPOINTS_KEY, savedEndpoints);
}

function renameEndpoint(from, to) {
  const value = to.trim();
  if (!value || value === from) return;
  savedEndpoints = savedEndpoints.map((e) => (e === from ? value : e));
  store.setList(ENDPOINTS_KEY, savedEndpoints);
}

// The session path the server was started with. It is relative on purpose:
// resolved against the page's own URL, the same build works on localhost, on
// a domain, and behind a relay, with nothing hardcoded anywhere.
const SESSION_PATH = (window.__WSSH__ && window.__WSSH__.sessionPath) || '/ws';

// endpointFor resolves the session address from wherever this page came from.
// A page served over https must reach a wss:// endpoint, and a relay puts the
// page on a host we could not have known at build time, so both are derived.
function endpointFor(loc) {
  const url = new URL(SESSION_PATH, loc.href);
  url.protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.toString();
}

// addrFromQuery reads ?addr=, so a session can be handed around as a link:
//
//     http://localhost:7070/?addr=ws://localhost:7171/ws
//
// The value is usually unencoded, which is why it is read as raw text rather
// than trusted to be a well-formed query parameter.
function addrFromQuery() {
  const raw = new URLSearchParams(location.search).get('addr');
  const value = raw && raw.trim();
  return value || null;
}

// syncQuery keeps the address bar in step with where we are pointed, so the
// URL can be copied or bookmarked and always names the target. It is done on
// connect rather than on every keystroke, which would churn history and leave
// half-typed addresses in the bar.
function syncQuery(addr) {
  const url = new URL(location.href);
  url.searchParams.set('addr', addr);
  history.replaceState(null, '', url);
}

const STATUS = {
  idle: { label: 'Disconnected', color: 'text-slate-400' },
  connecting: { label: 'Connecting…', color: 'text-amber-300' },
  connected: { label: 'Connected', color: 'text-emerald-400' },
  closed: { label: 'Session ended', color: 'text-slate-400' },
};

function App() {
  const containerRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const workerRef = useRef(null);
  // The terminal outlives React renders, so pending output and the current
  // geometry are held in refs rather than state: re-rendering on every byte
  // would put the whole component tree in the path of the data stream.
  const queueRef = useRef([]);

  const [status, setStatus] = useState('idle');
  const [error, setError] = useState('');
  const [user, setUser] = useState(() => store.get('wssh.user') || 'root');
  const [connected, setConnected] = useState(false);

  // The address is editable because the page does not have to be talking to
  // the server that served it: `wssh web --ui-only` is a client for a wssh
  // server somewhere else entirely.
  //
  // Three sources, in order: an ?addr= in the query string, which makes a
  // session link shareable; then whatever was last used here; then the origin
  // the page came from.
  const [endpoint, setEndpoint] = useState(() => {
    const fromQuery = addrFromQuery();
    if (fromQuery) return fromQuery;
    return store.get('wssh.endpoint') || endpointFor(location);
  });

  // The worker effect is registered once, so it cannot close over the current
  // endpoint; it reads it from here when a session comes up.
  const currentEndpoint = useRef(endpoint);

  const onEndpointChange = useCallback((value) => {
    setEndpoint(value);
    currentEndpoint.current = value;
    store.set('wssh.endpoint', value);
  }, []);

  const resetEndpoint = useCallback(() => {
    onEndpointChange(endpointFor(location));
    syncQuery(endpointFor(location));
  }, [onEndpointChange]);

  // --- the endpoint combobox -----------------------------------------------
  //
  // A plain text field forgets where you have been. This is a real list of
  // addresses that worked, kept in recency order, and it stays editable so a
  // typo can be corrected in place instead of retyped.

  // connect is defined further down; the key handler above needs it first.
  const connectRef = useRef(() => {});

  const [listOpen, setListOpen] = useState(false);
  const [saved, setSaved] = useState(savedEndpoints);
  const [editing, setEditing] = useState(null); // the entry being renamed
  const [editValue, setEditValue] = useState('');

  const refresh = useCallback((next) => {
    savedEndpoints = next;
    setSaved(next);
  }, []);

  // Filtering is driven by what has been typed into the field since it was
  // focused, not by whatever the field happens to hold. Otherwise focusing a
  // prefilled field would hide every entry that is not already in it, and the
  // list would look empty when there is history to show.
  const [filter, setFilter] = useState('');

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return saved;
    return saved.filter((e) => e.toLowerCase().includes(needle));
  }, [filter, saved]);

  const chooseEndpoint = useCallback((value) => {
    onEndpointChange(value);
    setFilter('');
    setListOpen(false);
  }, [onEndpointChange]);

  const commitRename = useCallback(() => {
    renameEndpoint(editing, editValue);
    refresh(store.getList(ENDPOINTS_KEY));
    setEditing(null);
  }, [editing, editValue, refresh]);

  const cancelRename = useCallback(() => {
    setEditing(null);
    setEditValue('');
  }, []);

  const onKeyDown = useCallback((e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      setListOpen(true);
      return;
    }
    if (e.key === 'Escape') {
      setListOpen(false);
      return;
    }
    if (e.key === 'Enter') {
      // Enter connects, but only after letting the list get out of the way.
      if (listOpen && visible.length > 0 && visible[0] !== endpoint) {
        chooseEndpoint(visible[0]);
        return;
      }
      connectRef.current();
    }
  }, [endpoint, listOpen, visible, chooseEndpoint]);


  // --- terminal lifecycle -------------------------------------------------

  useEffect(() => {
    const term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 14,
      scrollback: 5000,
      theme: {
        background: '#0f172a',
        foreground: '#e2e8f0',
        cursor: '#34d399',
        selectionBackground: '#334155',
      },
    });

    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    // WebGL keeps large repaints off the main thread. It is the first thing
    // to fail on machines without GPU access, so fall back silently.
    try {
      term.loadAddon(new WebglAddon.WebglAddon());
    } catch {
      /* software rendering is fine */
    }
    term.loadAddon(new ClipboardAddon.ClipboardAddon());

    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    // Drain anything the worker delivered before React was ready for it.
    for (const chunk of queueRef.current) term.write(chunk);
    queueRef.current = [];

    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        return;
      }
      // A resize has to become an SSH window-change request, or full-screen
      // programs keep drawing to the geometry they started with.
      workerRef.current?.postMessage({
        type: 'resize',
        cols: term.cols,
        rows: term.rows,
      });
    });
    observer.observe(containerRef.current);

    return () => {
      observer.disconnect();
      term.dispose();
      termRef.current = null;
    };
  }, []);

  // --- worker lifecycle ---------------------------------------------------

  useEffect(() => {
    const worker = new Worker('./worker.js');
    workerRef.current = worker;

    worker.onmessage = (event) => {
      const msg = event.data;
      switch (msg.type) {
        case 'data': {
          const chunk = new Uint8Array(msg.payload);
          if (termRef.current) {
            termRef.current.write(chunk);
          } else {
            queueRef.current.push(chunk);
          }
          break;
        }
        case 'connected':
          setStatus('connected');
          setConnected(true);
          // Only an address that actually worked is worth remembering.
          if (currentEndpoint.current) {
            rememberEndpoint(currentEndpoint.current);
            refresh(store.getList(ENDPOINTS_KEY));
          }
          termRef.current?.focus();
          break;
        case 'closed':
          setStatus('closed');
          setConnected(false);
          break;
        case 'error':
          setError(msg.message);
          setStatus('closed');
          setConnected(false);
          break;
        default:
          break;
      }
    };

    worker.onerror = (event) => {
      setError(event.message || 'worker failed to start');
      setStatus('closed');
    };

    return () => {
      worker.terminate();
      workerRef.current = null;
    };
  }, []);

  // --- input --------------------------------------------------------------

  useEffect(() => {
    const term = termRef.current;
    if (!term) return undefined;

    const dataSub = term.onData((data) => {
      workerRef.current?.postMessage({
        type: 'input',
        data: new TextEncoder().encode(data),
      });
    });

    return () => dataSub.dispose();
  }, [status]);

  // Clicking anywhere in the terminal should focus it, the way a real one does.
  const focusTerminal = useCallback(() => termRef.current?.focus(), []);

  const connect = useCallback(() => {
    const url = endpoint.trim();
    // A mistyped address otherwise fails deep inside the WebSocket handshake,
    // where the message is about the connection rather than the typing.
    if (!/^wss?:\/\//i.test(url)) {
      setError(`"${url}" is not a WebSocket address; it should start with ws:// or wss://`);
      setStatus('idle');
      return;
    }
    setError('');
    setStatus('connecting');
    syncQuery(url);
    const term = termRef.current;
    workerRef.current?.postMessage({
      type: 'connect',
      url,
      user: user.trim() || 'root',
      cols: term?.cols ?? 80,
      rows: term?.rows ?? 24,
    });
  }, [endpoint, user]);

  // The address key handler runs before connect is declared, so it calls
  // through this.
  connectRef.current = connect;

  const disconnect = useCallback(() => {
    workerRef.current?.postMessage({ type: 'disconnect' });
    setStatus('idle');
    setConnected(false);
  }, []);

  const statusInfo = STATUS[status] ?? STATUS.idle;

  return html`
    <div class="h-full flex flex-col">
      <header class="flex items-center gap-2 px-4 py-2 bg-slate-900 border-b border-slate-800">
        <span class="font-semibold tracking-tight shrink-0">wssh</span>
        <label class="sr-only" for="endpoint">WebSocket address</label>
        <div class="flex-1 min-w-0 flex">
          <div
            class="relative flex-1 min-w-0"
            onBlur=${(e) => {
              // Close only when focus leaves the whole control, not just the
              // text field. Renaming swaps a row for an input and focuses it,
              // which blurs the field and would otherwise slam the list shut
              // mid-edit.
              if (!e.currentTarget.contains(e.relatedTarget)) setListOpen(false);
            }}
          >
            <input
              id="endpoint"
              class="w-full min-w-0 bg-slate-800 border border-slate-700 rounded-l px-2 py-1
                     font-mono text-xs focus:outline-none focus:border-emerald-500
                     disabled:opacity-50"
              value=${endpoint}
              spellcheck="false"
              autocomplete="off"
              title="WebSocket address of the wssh server to connect to"
              disabled=${connected || status === 'connecting'}
              onInput=${(e) => { onEndpointChange(e.target.value); setFilter(e.target.value); setListOpen(true); }}
              onFocus=${() => { setFilter(''); setListOpen(true); }}
              onKeyDown=${onKeyDown}
            />
        ${listOpen && saved.length > 0 && html`
          <div
            class="absolute z-20 mt-1 w-full max-h-72 overflow-y-auto rounded
                   border border-slate-700 bg-slate-900 shadow-xl"
          >
            ${visible.length === 0 && html`
              <div class="px-3 py-2 text-xs text-slate-500">nothing remembered yet</div>`}
            ${visible.map((entry) => html`
              <div
                key=${entry}
                class="group flex items-center gap-1 px-1 hover:bg-slate-800"
              >
                ${editing === entry
                  ? html`<input
                      class="flex-1 min-w-0 bg-slate-950 border border-emerald-600 rounded
                             px-2 py-1 font-mono text-xs focus:outline-none"
                      value=${editValue}
                      autoFocus
                      spellcheck="false"
                      autocomplete="off"
                      title="Enter saves, Escape cancels"
                      onFocus=${(e) => e.target.select()}
                      onInput=${(e) => setEditValue(e.target.value)}
                      onKeyDown=${(e) => {
                        if (e.key === 'Enter') commitRename();
                        if (e.key === 'Escape') cancelRename();
                      }}
                    />
                    <button
                      class="px-1.5 py-1 text-xs text-emerald-400 hover:text-emerald-300"
                      title="Save this address"
                      onClick=${commitRename}
                    >✓</button>
                    <button
                      class="px-1.5 py-1 text-xs text-slate-500 hover:text-slate-200"
                      title="Cancel"
                      onClick=${cancelRename}
                    >✗</button>`
                  : html`<button
                      class="flex-1 min-w-0 text-left px-2 py-1 font-mono text-xs
                             truncate text-slate-300 hover:text-emerald-300"
                      title=${entry}
                      onClick=${() => chooseEndpoint(entry)}
                    >${entry}</button>
                    <button
                      class="px-1.5 py-1 text-xs text-slate-500 hover:text-emerald-300"
                      title="Rename"
                      onClick=${() => { setEditing(entry); setEditValue(entry); }}
                    >✎</button>
                    <button
                      class="px-1.5 py-1 text-xs text-slate-500 hover:text-red-400"
                      title="Forget"
                      onClick=${() => {
                        forgetEndpoint(entry);
                        refresh(store.getList(ENDPOINTS_KEY));
                      }}
                    >✕</button>`}
              </div>`)}
          </div>`}
          </div>
          <button
            class="shrink-0 px-2 bg-slate-800 border border-l-0 border-slate-700 rounded-r
                   text-slate-400 hover:text-slate-200 hover:bg-slate-700 disabled:opacity-50"
            title="Remembered addresses"
            disabled=${connected || status === 'connecting'}
            onMouseDown=${(e) => e.preventDefault()}
            onClick=${() => { setFilter(''); setListOpen((open) => !open); }}
          >▾</button>

        </div>
        <button
          class="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300
                 disabled:opacity-50"
          title="Point back at this page's own server"
          disabled=${connected || status === 'connecting'}
          onClick=${resetEndpoint}>reset</button>
        <label class="sr-only" for="user">user</label>
        <input
          id="user"
          class="w-24 shrink-0 bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm
                 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
          value=${user}
          disabled=${connected || status === 'connecting'}
          onInput=${(e) => { setUser(e.target.value); store.set('wssh.user', e.target.value); }}
          onKeyDown=${(e) => { if (e.key === 'Enter' && !connected) connect(); }}
        />
        ${connected || status === 'connecting'
          ? html`<button
              class="px-3 py-1 text-sm rounded bg-slate-700 hover:bg-slate-600 shrink-0"
              onClick=${disconnect}>Disconnect</button>`
          : html`<button
              class="px-3 py-1 text-sm rounded bg-emerald-600 hover:bg-emerald-500
                     text-slate-900 font-medium shrink-0"
              onClick=${connect}>Connect</button>`}
        <span class=${`text-xs shrink-0 ${statusInfo.color}`}>${statusInfo.label}</span>
      </header>

      ${error && html`
        <div class="px-4 py-2 bg-red-950/60 border-b border-red-900 text-sm text-red-300">
          ${error}
        </div>`}

      <main
        ref=${containerRef}
        onClick=${focusTerminal}
        class="flex-1 min-h-0 p-2 overflow-hidden"
      ></main>
    </div>
  `;
}

createRoot(document.getElementById('root')).render(html`<${App} />`);
