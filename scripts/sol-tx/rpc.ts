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
    [b64, { encoding: "base64", preflightCommitment: "confirmed" }],
    verbose,
  );
  return r;
}

export interface SignatureStatus {
  confirmationStatus?: "processed" | "confirmed" | "finalized";
  confirmations: number | null;
  err: unknown;
  slot: number;
}

interface SignatureStatusesResult {
  context: { slot: number };
  value: (SignatureStatus | null)[];
}

/**
 * Polls the cluster for the status of a transaction signature until it
 * reaches a terminal state (confirmed/finalized, or an error). Returns the
 * final status so the caller can read the err field; a non-nil err means
 * the transaction was included in a block but its instructions failed.
 *
 * sendTransaction followed by getSignatureStatuses is the post-1.10
 * confirmation flow. The older confirmTransaction helper exists on some
 * clusters (notably local validators) but not on mainnet-beta, where it
 * answers -32601 "Method not found".
 */
export async function confirmTransaction(
  endpoint: string,
  signature: string,
  verbose = false,
): Promise<SignatureStatus> {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const deadline = Date.now() + 90_000; // 90s is generous; mainnet finalizes in seconds
  while (Date.now() < deadline) {
    const r = await call<SignatureStatusesResult>(
      endpoint,
      "getSignatureStatuses",
      [[signature], { searchTransactionHistory: true }],
      verbose,
    );
    const status = r.value[0];
    if (status !== null) {
      if (status.err) {
        throw new Error(`the transaction failed: ${JSON.stringify(status.err)}`);
      }
      if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") {
        return status;
      }
    }
    await sleep(2_000);
  }
  throw new Error(`signature ${signature} did not confirm within 90s`);
}
// The cluster an endpoint belongs to, or null when it cannot be told.
//
// Only the public Solana endpoints are recognised. Someone's own RPC carries no
// cluster in its URL, and calling that mainnet would print a link to a page
// that says the transaction does not exist, which is worse than printing no
// link at all.
export type Cluster = "mainnet" | "devnet" | "testnet";

export function clusterOf(endpoint: string): Cluster | null {
  let host: string;
  try {
    host = new URL(endpoint).hostname.toLowerCase();
  } catch {
    return null;
  }
  switch (host) {
    case "api.mainnet-beta.solana.com":
      return "mainnet";
    case "api.devnet.solana.com":
      return "devnet";
    case "api.testnet.solana.com":
      return "testnet";
    default:
      return null;
  }
}

// The explorer's link to a confirmed transaction, or "" when the cluster
// behind the endpoint cannot be named.
//
// solscan picks the cluster with a query parameter rather than a path, so
// mainnet is the bare URL and the other two carry ?cluster=.
export function explorerTxURL(endpoint: string, signature: string): string {
  const cluster = clusterOf(endpoint);
  if (!cluster) return "";
  const base = `https://solscan.io/tx/${signature}`;
  return cluster === "mainnet" ? base : `${base}?cluster=${cluster}`;
}
