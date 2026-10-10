// scripts/sol-tx/rpc_test.ts
//
// What is worth testing here is the polling and the two ways a transaction can
// come back wrong. Everything else in rpc.ts is a straight line to fetch, and a
// test over that would only be asserting the wording of an error message
// against a fixture written to match it.
//
// The two that matter are the two where being wrong costs money: a signature
// the cluster has not seen yet answers null and must not be read as confirmed,
// and a transaction that lands but fails its instructions must be raised rather
// than printed as a success.

import { assertEquals, assertRejects } from "jsr:@std/assert";
import * as rpc from "./rpc.ts";

// runWithServer starts a server on a free port, hands the URL to the test,
// and tears it down afterwards.
//
// The wait for the listen is on onListen rather than on server.finished.
// server.finished settles when the server *stops*, so awaiting it to mean
// "ready" deadlocks: the server never stops until the test finishes, and the
// test never starts. onListen is the one that fires when the port is bound,
// which is what the fetch below needs.
async function runWithServer(
  handler: (req: Request) => Response,
  run: (url: string) => Promise<void>,
): Promise<void> {
  const ac = new AbortController();
  let listening: () => void;
  const bound = new Promise<void>((resolve) => {
    listening = resolve;
  });
  const server = Deno.serve(
    { port: 0, signal: ac.signal, onListen: () => listening() },
    handler,
  );
  try {
    await bound;
    const { port } = server.addr as Deno.NetAddr;
    await run(`http://127.0.0.1:${port}`);
  } finally {
    ac.abort();
    // Let the abort land before the test ends, so the listener is not left
    // holding a port into the next test's noise.
    await server.finished.catch(() => {});
  }
}

Deno.test("confirmTransaction polls getSignatureStatuses and returns the status", async () => {
  // The fake server answers the first call with null (signature unknown yet)
  // and the second with a confirmed status. confirmTransaction should loop
  // and return the second answer rather than throwing on the first.
  let calls = 0;
  await runWithServer(
    () => {
      calls++;
      const body = calls === 1
        ? { jsonrpc: "2.0", result: { context: { slot: 1 }, value: [null] }, id: 1 }
        : {
          jsonrpc: "2.0",
          result: {
            context: { slot: 5 },
            value: [{
              confirmationStatus: "confirmed",
              confirmations: 1,
              err: null,
              slot: 5,
            }],
          },
          id: 1,
        };
      return new Response(JSON.stringify(body), {
        headers: { "Content-Type": "application/json" },
      });
    },
    async (endpoint) => {
      const status = await rpc.confirmTransaction(endpoint, "fakesig", false);
      assertEquals(status.confirmationStatus, "confirmed");
      assertEquals(status.slot, 5);
      assertEquals(status.err, null);
      assertEquals(calls >= 2, true);
    },
  );
});

Deno.test("confirmTransaction surfaces the transaction error when one is set", async () => {
  await runWithServer(
    () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          result: {
            context: { slot: 5 },
            value: [{
              confirmationStatus: "confirmed",
              confirmations: 1,
              err: { InstructionError: [2, "MissingAccount"] },
              slot: 5,
            }],
          },
          id: 1,
        }),
        { headers: { "Content-Type": "application/json" } },
      ),
    async (endpoint) => {
      await assertRejects(
        async () => await rpc.confirmTransaction(endpoint, "fakesig", false),
        Error,
        "MissingAccount",
      );
    },
  );
});
// The explorer link is only correct if the cluster matches the endpoint, so
// the cases that matter are the four: the three public clusters and a private
// RPC, which gets no link at all rather than a wrong one.
Deno.test("explorerTxURL names the cluster the endpoint belongs to", () => {
  const sig = "54DxBZKPwS9mBmcxiCodw5updkq2pHAu9CZF7b2tNqv7WYVjmyKDoaTcDViQDEQXNcbFUjG4W9EB19W4hqYnYhwX";
  const cases: [string, string][] = [
    ["https://api.mainnet-beta.solana.com", `https://solscan.io/tx/${sig}`],
    ["https://api.devnet.solana.com", `https://solscan.io/tx/${sig}?cluster=devnet`],
    ["https://api.testnet.solana.com", `https://solscan.io/tx/${sig}?cluster=testnet`],
    // The host is matched case-insensitively: a URL typed by hand is
    // routinely capitalised, and DNS does not care.
    ["https://API.Mainnet-Beta.Solana.com", `https://solscan.io/tx/${sig}`],
    // A path on the endpoint is not part of the host.
    ["https://api.devnet.solana.com/rpc", `https://solscan.io/tx/${sig}?cluster=devnet`],
  ];
  for (const [endpoint, want] of cases) {
    assertEquals(rpc.explorerTxURL(endpoint, sig), want);
  }
});

Deno.test("a private endpoint gets no explorer link", () => {
  // A private RPC says nothing about which cluster it fronts, and a mainnet
  // link to a devnet transaction is a page that says the transaction does not
  // exist. No link beats a wrong one.
  assertEquals(rpc.explorerTxURL("https://my-rpc.example.com", "sig"), "");
  assertEquals(rpc.explorerTxURL("not a url", "sig"), "");
  assertEquals(rpc.clusterOf("https://my-rpc.example.com"), null);
});
