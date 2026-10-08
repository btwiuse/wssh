// app.js — the terminal UI.
//
// No bundler: React and htm come from esm.sh via the import map in
// index.html, and xterm.js is a plain global from jsDelivr.

import React, { useCallback, useEffect, useRef, useState } from 'react';
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
};

// The WebSocket endpoint this page serves by default: its own origin.
function endpointFor(loc) {
  const scheme = loc.protocol === 'https:' ? 'wss' : 'ws';
  return `${scheme}://${loc.host}/ws`;
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
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    return store.get('wssh.endpoint') || `${scheme}://${location.host}/ws`;
  });

  const onEndpointChange = useCallback((value) => {
    setEndpoint(value);
    store.set('wssh.endpoint', value);
  }, []);

  const resetEndpoint = useCallback(() => {
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    onEndpointChange(`${scheme}://${location.host}/ws`);
    syncQuery(endpointFor(location));
  }, [onEndpointChange]);

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

  const disconnect = useCallback(() => {
    workerRef.current?.postMessage({ type: 'disconnect' });
    setStatus('idle');
    setConnected(false);
  }, []);

  const statusInfo = STATUS[status] ?? STATUS.idle;

  return html`
    <div class="h-full flex flex-col">
      <header class="flex items-center gap-2 px-4 py-2 bg-slate-900 border-b border-slate-800">
        <span class="font-semibold tracking-tight shrink-0">webssh</span>
        <label class="sr-only" for="endpoint">WebSocket address</label>
        <input
          id="endpoint"
          class="flex-1 min-w-0 bg-slate-800 border border-slate-700 rounded px-2 py-1
                 font-mono text-xs focus:outline-none focus:border-emerald-500
                 disabled:opacity-50"
          value=${endpoint}
          spellcheck="false"
          autocomplete="off"
          title="WebSocket address of the wssh server to connect to"
          disabled=${connected || status === 'connecting'}
          onInput=${(e) => onEndpointChange(e.target.value)}
          onKeyDown=${(e) => { if (e.key === 'Enter' && !connected) connect(); }}
        />
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
