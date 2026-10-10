// worker.js — a classic Web Worker that hosts the Go/WASM SSH client.
//
// The SSH session lives here rather than on the main thread so xterm.js keeps
// rendering smoothly while the WebAssembly runtime is busy with key exchange
// and decryption. The two sides talk in plain postMessage: input and control go
// down, terminal output and status come back up.

importScripts('./wasm_exec.js');

const go = new Go();

// client/main.go calls self.websshGoExportResolve(...) once it is running.
// The promise is created first so it is already waiting when go.run executes.
const exportedPromise = new Promise((resolve) => {
  self.websshGoExportResolve = resolve;
});

// Held as a plain variable rather than awaited at each use. The input path in
// particular must never await anything: two flushes that each await can resume
// in the opposite order to the one they were queued in, which scrambles the
// keystrokes.
let api = null;
exportedPromise.then((a) => { api = a; });

(async () => {
  try {
    const res = await fetch('./ssh.wasm');
    if (!res.ok) throw new Error(`ssh.wasm: HTTP ${res.status}`);
    const result = await WebAssembly.instantiateStreaming(res, go.importObject);
    // go.run() is not expected to return: the Go program blocks forever on
    // purpose. Surface it if it ever does, because every later call into the
    // runtime then fails with a message that points nowhere useful.
    go.run(result.instance).then(
      () => postMessage({ type: 'error', message: 'go.run() returned: the Go program exited' }),
      (err) => postMessage({ type: 'error', message: `go.run() rejected: ${err}` }),
    );
  } catch (err) {
    postMessage({ type: 'error', message: `could not load ssh.wasm: ${err.message}` });
  }
})();

// --- input batching ---------------------------------------------------------
//
// Every crossing into Go resumes the WebAssembly runtime, and a fast typist
// produces one key event per character. Queue them and hand Go a single merged
// write, in the order the keys were pressed.

let pendingInput = [];
let flushScheduled = false;

function scheduleFlush() {
  if (flushScheduled) return;
  flushScheduled = true;
  setTimeout(flushInput, 0);
}

function flushInput() {
  if (pendingInput.length > 0) {
    let total = 0;
    for (const chunk of pendingInput) total += chunk.length;
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of pendingInput) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }
    pendingInput = [];

    if (api) {
      try {
        api.write(merged);
      } catch (err) {
        postMessage({ type: 'error', message: String(err) });
      }
    }
  }
  flushScheduled = false;
}

// --- helpers ----------------------------------------------------------------

// Prompts have to make a round trip: a worker's globals are not the page's,
// so a hook installed by the page is invisible from here, and Go can only see
// this worker's scope. Each request goes out as a message and the answer comes
// back the same way.
let nextPromptId = 0;
const pendingPrompts = new Map();

function askPage(kind, name, detail) {
  const id = ++nextPromptId;
  return new Promise((resolve) => {
    pendingPrompts.set(id, resolve);
    postMessage({ type: 'prompt', id, kind, name: name || '', detail: detail || '' });
  });
}

// Handed to Go: each returns a promise, which Go awaits inside the handshake
// or, for the signature, inside an agent request.
globalThis.__websshAskPassword = () => askPage('password');
globalThis.__websshAskPassphraseFn = (name) => askPage('passphrase', name);

// The signature question is the one that can arrive long after the session
// started and as often as the far end likes, so it carries its own summary
// rather than a key name. The answer is yes or no, and "no" is a real answer
// rather than a failure.
globalThis.__websshAskSignature = (summary) => askPage('signature', '', summary);

// Answering a prompt the page has shown.
function answerPrompt(id, value) {
  const resolve = pendingPrompts.get(id);
  if (resolve) {
    pendingPrompts.delete(id);
    resolve(value);
  }
}

function apiGenerate(msg) {
  exportedPromise.then((api) => api.generateKey(msg.kind, msg.bits || 0))
    .catch((err) => postMessage({ type: 'error', message: String(err) }));
}

// --- message pump -----------------------------------------------------------

self.onmessage = async (event) => {
  const msg = event.data;
  if (msg.type === 'promptAnswer') {
    answerPrompt(msg.id, msg.value);
    return;
  }
  try {
    const api = await exportedPromise;
    switch (msg.type) {
      case 'input':
        pendingInput.push(msg.data);
        scheduleFlush();
        return;
      case 'connect': {
        // Connecting is the one place worth waiting: nothing may be sent to
        // the runtime before it has finished booting.
        const api = await exportedPromise;
        // Credentials go across as one JSON blob and the page supplies the
        // passphrase and password callbacks, so neither ever passes through
        // this worker as data. The optional command is forwarded verbatim:
        // empty means an interactive shell, anything else is run on the far
        // side and the session ends when it does.
        const credentials = JSON.stringify(msg.credentials || { keys: [], passwords: [] });
        api.connect(msg.url, msg.user, msg.cols, msg.rows, credentials,
                   globalThis.__websshAskPassword, msg.command || '');
        return;
      }
      case 'generateKey':
        apiGenerate(msg);
        return;
      case 'keyInfo': {
        const api = await exportedPromise;
        api.keyInfo(msg.privateKey);
        return;
      }
      case 'resize':
        if (api) api.resize(msg.cols, msg.rows);
        return;
      case 'disconnect':
        if (api) api.disconnect();
        return;
      default:
        postMessage({ type: 'error', message: `unknown message: ${msg.type}` });
    }
  } catch (err) {
    postMessage({ type: 'error', message: String(err) });
  }
};
