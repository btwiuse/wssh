// scripts/sol-tx/rpc.ts
//
// Thin JSON-RPC client for the Solana HTTP API. Just enough surface for
// getLatestBlockhash, sendTransaction, and confirmTransaction. Every error
// carries the URL the request went to so that a DNS or middlebox problem
// shows up in the output rather than as a generic network error.

interface JsonRpcResponse<T> {
  result?: T;
  error?: { code: number; message: string };
}

async function call<T>(
  endpoint: string,
  method: string,
  params: unknown[],
  verbose = false,
): Promise<T> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method,
    params,
  });
  if (verbose) console.error(`[rpc] POST ${endpoint}  ${method}`);

  let resp: Response;
  try {
    resp = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
  } catch (err) {
    throw new Error(`${endpoint}: ${(err as Error).message}`);
  }

  if (!resp.ok) {
    throw new Error(`${endpoint} answered ${resp.status} ${resp.statusText}`);
  }

  const text = await resp.text();
  let parsed: JsonRpcResponse<T>;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      `${endpoint} answered with a non-JSON body (${text.length} bytes): ${
        text.slice(0, 120)
      }`,
    );
  }

  if (parsed.error) {
    const { code, message } = parsed.error;
    if (code === -32601) {
      throw new Error(`${endpoint} does not implement ${method}: ${message}`);
    }
    if (code !== 0) {
      throw new Error(`${endpoint} refused the call (code ${code}): ${message}`);
    }
    throw new Error(`${endpoint} refused the call: ${message}`);
  }

  return parsed.result as T;
}

interface BlockhashResult {
  context: { slot: number };
  value: { blockhash: string; lastValidBlockHeight: number };
}

export async function getLatestBlockhash(endpoint: string, verbose = false): Promise<string> {
  const r = await call<BlockhashResult>(
    endpoint,
    "getLatestBlockhash",
    [{ commitment: "finalized" }],
    verbose,
  );
  return r.value.blockhash;
}

export async function sendTransaction(
  endpoint: string,
  signedTx: Uint8Array,
  verbose = false,
): Promise<string> {
  // Solana expects the signed transaction as a base64 string in JSON-RPC.
  const b64 = btoa(String.fromCharCode(...signedTx));
  const r = await call<string>(
    endpoint,
    "sendTransaction",
    [b64, { encoding: "base64", skipPreflight: true, preflightCommitment: "confirmed" }],
    verbose,
  );
  return r;
}

export async function confirmTransaction(
  endpoint: string,
  signature: string,
  verbose = false,
): Promise<void> {
  // Solana RPC since 1.10 returns the same response whether confirmTransaction
  // is polling or just recording; older clusters exposed it as a polling
  // helper. Both shape the same way for our purposes: nil result means yes.
  await call<unknown>(endpoint, "confirmTransaction", [signature, { commitment: "confirmed" }], verbose);
}