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

// --- message pump -----------------------------------------------------------

self.onmessage = (event) => {
  const msg = event.data;
  try {
    switch (msg.type) {
      case 'input':
        pendingInput.push(msg.data);
        scheduleFlush();
        return;
      case 'connect':
        // Connecting is the one place worth waiting: nothing may be sent to
        // the runtime before it has finished booting.
        exportedPromise.then((a) => {
          a.connect(msg.url, msg.user, msg.cols, msg.rows);
        }).catch((err) => {
          postMessage({ type: 'error', message: String(err) });
        });
        return;
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
