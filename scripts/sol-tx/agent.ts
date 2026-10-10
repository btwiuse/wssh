// scripts/sol-tx/agent.ts
//
// Talks to the wssh SSH agent over a unix socket. The wire format is the
// upstream ssh-agent protocol (PROTOCOL.agent in x/crypto/ssh/agent) plus
// one custom extension named "solana-tx@wssh". The extension carries a
// JSON SolanaTxRequest as the contents and answers with a JSON
// SolanaTxResponse.
//
// The point of writing this by hand rather than reaching for npm/ssh-agent
// is that the protocol is small, stable, and worth being able to read.
// Every byte on the wire is annotated in verbose mode, which is what makes
// this script useful for debugging a wallet connection that is misbehaving.

import { encodeBase58 } from "./base58.ts";

export interface SolanaAccount {
  address: string;
  isSigner: boolean;
  isWritable: boolean;
}

export interface SolanaInstruction {
  programId: string;
  accounts: SolanaAccount[];
  /** base58-encoded instruction data */
  data: string;
}

export interface SolanaTxRequest {
  blockhash: string;
  label?: string;
  /** The key that signs. Also the fee payer: Solana requires that. */
  signer?: string;
  instructions: SolanaInstruction[];
}

export interface SolanaTxResponse {
  refusal?: string;
  signature?: string; // hex of the 64-byte ed25519 signature
  /** base64 of the wire-format signed transaction */
  signedTransaction?: string;
}

/** Decode the base64-encoded signed transaction from a response. */
export function signedTransactionBytes(resp: SolanaTxResponse): Uint8Array {
  if (!resp.signedTransaction) {
    throw new Error("the agent returned no signed transaction");
  }
  return Uint8Array.from(atob(resp.signedTransaction), (c) => c.charCodeAt(0));
}

const EXTENSION_NAME = "solana-tx@wssh";

// ssh-agent message types, from PROTOCOL.agent.
const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENT_SUCCESS = 6;
const SSH_AGENT_EXTENSION = 27; // not used by us, kept for completeness
const SSH_AGENT_EXTENSION_FAILURE = 28;

const MAX_RESPONSE_BYTES = 64 << 20; // 64 MiB; the upstream default cap

// SSH string: 4-byte big-endian length, then the bytes (no NUL terminator).
// SSH uint32: 4-byte big-endian. That is the whole marshalling format this
// extension uses, which is why a hand-rolled encoder is shorter than pulling
// in ssh2 or similar.
function writeSSHString(buf: number[], s: string | Uint8Array): void {
  const bytes = typeof s === "string" ? new TextEncoder().encode(s) : s;
  const len = bytes.length;
  buf.push((len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
  for (const b of bytes) buf.push(b);
}

function marshalExtensionRequest(name: string, contents: Uint8Array): Uint8Array {
  // Wire shape, per PROTOCOL.agent and the upstream x/crypto/ssh/agent
  // extensionAgentMsg struct:
  //
  //   byte  sshtype = 27 (SSH_AGENT_EXTENSION)
  //   string  ExtensionType
  //   byte[]  Contents, tagged `ssh:"rest"` — written verbatim, NO length prefix
  //
  // The "rest" tag is the gotcha: a []byte field with that tag does not
  // carry its own length, because the receiver reads it as the remainder of
  // the message. Writing a 4-byte length in front of it produces a Contents
  // value that starts with four garbage bytes, and the extension handler
  // then fails to parse the JSON it thought it was handed.
  const buf: number[] = [];
  buf.push(SSH_AGENT_EXTENSION);
  writeSSHString(buf, name);
  for (const b of contents) buf.push(b);
  return new Uint8Array(buf);
}

function readExtensionReply(buf: Uint8Array): { ok: boolean; payload: Uint8Array } {
  // The reply wire format depends on what the extension returned and how the
  // upstream server marshalled it. The upstream Go server wraps the extension
  // result in a struct with a single []byte "rest" field tagged `ssh:"rest"`,
  // which marshals with no leading message-type byte - the entire body is the
  // JSON the extension produced. Failure cases prepend a single byte:
  //   5  = SSH_AGENT_FAILURE, returned for a real ssh-agent that has no
  //        extension handler. The body is empty.
  //   28 = SSH_AGENT_EXTENSION_FAILURE, returned when the handler ran but
  //        produced an error. The body that follows is whatever the extension
  //        returned in its failure path.
  //
  // The Go wssh agent always answers with JSON (SolanaTxResponse), so any
  // non-empty body is parsed as JSON. An empty body is taken as success-but-
  // empty and reported.
  if (buf.length === 0) {
    return { ok: false, payload: new Uint8Array(0) };
  }
  switch (buf[0]) {
    case SSH_AGENT_FAILURE:
      return { ok: false, payload: new Uint8Array(0) };
    case SSH_AGENT_EXTENSION_FAILURE:
      return { ok: false, payload: buf.subarray(1) };
    default:
      // Success: the whole body is the JSON the extension returned. The
      // upstream server does NOT prefix success with a byte for this struct
      // shape, because it has no `sshtype` tag.
      return { ok: true, payload: buf };
  }
}

// ---------------------------------------------------------------------------

export async function ask(
  sockPath: string,
  req: SolanaTxRequest,
  verbose = false,
): Promise<SolanaTxResponse> {
  if (verbose) {
    console.error(`[agent] connecting to ${sockPath}`);
  }

  // Deno does not yet expose a connect() for arbitrary unix sockets in a
  // stable way across versions; the Deno 2 idiom is Deno.connect with
  // {path: ...}. That requires --allow-sys or --unstable-sys depending on
  // the version; the deno.json task wires that up.
  const conn = await Deno.connect({ path: sockPath, transport: "unix" });

  try {
    const body = new TextEncoder().encode(JSON.stringify(req));
    const framed = marshalExtensionRequest(EXTENSION_NAME, body);

    if (verbose) {
      console.error(`[agent] request  ${framed.length} bytes`);
      console.error(`[agent]   extension: ${EXTENSION_NAME}`);
      console.error(`[agent]   contents: ${body.length} bytes JSON`);
      console.error(`[agent]   contents-text: ${new TextDecoder().decode(body)}`);
    }

    await writeFramed(conn, framed);

    const reply = await readFramed(conn);
    if (reply === null) {
      throw new Error("the agent closed the connection without answering");
    }

    if (verbose) {
      console.error(`[agent] reply    ${reply.length} bytes`);
      const hex = Array.from(reply).map((b) => b.toString(16).padStart(2, "0")).join(" ");
      console.error(`[agent]   hex: ${hex}`);
    }

    const { ok, payload } = readExtensionReply(reply);
    if (!ok) {
      if (reply.length === 0 || reply[0] === SSH_AGENT_FAILURE) {
        throw new Error(
          "this agent does not sign Solana transactions. If it is a real " +
            "ssh-agent you do not need this command: it will sign anything " +
            "you ask of it, so git push and ssh-keygen work as they always " +
            "have. Otherwise it is a browser agent with no wallet attached, " +
            "which needs one, and the agent forwarding that reaches it",
        );
      }
      throw new Error(`the agent refused to sign: ${new TextDecoder().decode(payload)}`);
    }

    const jsonText = new TextDecoder().decode(payload);
    let parsed: SolanaTxResponse;
    try {
      parsed = JSON.parse(jsonText) as SolanaTxResponse;
    } catch (err) {
      // The body was supposed to be JSON; surface the bytes on stderr so the
      // caller can see what shape the agent actually returned. Without this
      // an off-by-one in the wire format looks like "JSON parse error" with
      // nothing to pin it on.
      console.error(`[agent] payload ${payload.length} bytes (not JSON):`);
      const hex = Array.from(payload).map((b) => b.toString(16).padStart(2, "0")).join(" ");
      console.error(`[agent]   hex: ${hex}`);
      console.error(`[agent]   text: ${jsonText}`);
      throw new Error(`the agent's answer is not readable JSON: ${(err as Error).message}`);
    }
    if (verbose) {
      if (parsed.refusal) console.error(`[agent] refusal: ${parsed.refusal}`);
      else if (parsed.signedTransaction) {
        const txBytes = Uint8Array.from(atob(parsed.signedTransaction));
        console.error(`[agent] signed tx: ${txBytes.length} bytes`);
      }
    }
    return parsed;
  } finally {
    try {
      conn.close();
    } catch {
      // best-effort; the agent may have closed already
    }
  }
}

// -- low-level framing ------------------------------------------------------

/** One key the agent holds, in the form both scripts name it in. */
export interface AgentKey {
  type: string;
  /** base58, for an ed25519 key; empty for anything that cannot sign Solana */
  address: string;
  comment: string;
}

/**
 * List the keys the agent holds.
 *
 * The same question the Go side answers with solana.ListAgentKeysAt, asked
 * the same way: SSH_AGENTC_REQUEST_IDENTITIES, whose answer is a type, a key
 * blob and a comment per key. It exists so a command can say what is on offer
 * *before* it asks anything to sign, which is the only point at which that is
 * useful - afterwards the signature has already been given.
 */
export async function list(sockPath: string, verbose = false): Promise<AgentKey[]> {
  const conn = await Deno.connect({ path: sockPath, transport: "unix" });
  try {
    if (verbose) {
      console.error(`[agent] listing the keys it holds`);
    }
    await writeFramed(conn, new Uint8Array([SSH_AGENTC_REQUEST_IDENTITIES]));

    const reply = await readFramed(conn);
    if (reply === null || reply.length === 0) {
      throw new Error("the agent closed without listing its keys");
    }
    if (reply[0] === SSH_AGENT_FAILURE) {
      throw new Error("the agent refused to say what it holds");
    }
    if (reply[0] !== SSH_AGENT_IDENTITIES_ANSWER) {
      throw new Error(`the agent answered the key listing with ${reply[0]}, not an identities answer`);
    }
    return parseIdentities(reply);
  } finally {
    conn.close();
  }
}

/**
 * Read the keys out of a complete identities answer, type byte and all.
 *
 * After the type byte comes a uint32 count, and then that many records of
 * **two** fields: the key blob and a comment. There is no separate type field,
 * which is the part worth writing down - the algorithm name is inside the blob
 * rather than beside it, so a reader that expects `type, blob, comment` reads
 * the blob as the type and then walks off the end of the message. That is what
 * x/crypto/ssh/agent's marshalKey writes, and therefore what OpenSSH writes.
 *
 * The blob of an ed25519 key is `[4][ssh-ed25519][4][32 bytes]`, so the
 * address is those 32 bytes - the same reading solana/keys.go does, and for
 * the same reason: an ed25519 public key *is* a Solana account.
 */
function parseIdentities(buf: Uint8Array): AgentKey[] {
  if (buf.length < 5 || buf[0] !== SSH_AGENT_IDENTITIES_ANSWER) {
    throw new Error(
      `expected an identities answer, got message type ${buf[0] ?? "nothing"}`,
    );
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let at = 1;

  const readString = (): Uint8Array => {
    if (at + 4 > buf.length) throw new Error("the identities answer ended mid-string");
    const len = view.getUint32(at, false);
    at += 4;
    if (at + len > buf.length) throw new Error("the identities answer claimed a string past its end");
    const out = buf.subarray(at, at + len);
    at += len;
    return out;
  };

  if (at + 4 > buf.length) {
    throw new Error("the identities answer carried no key count");
  }
  const count = view.getUint32(at, false);
  at += 4;

  const decoder = new TextDecoder();
  const keys: AgentKey[] = [];
  for (let i = 0; i < count; i++) {
    const blob = readString();
    // A comment is optional: an agent with none to give may leave it off
    // rather than send an empty string, and treating a missing one as a
    // length prefix is how the rest of the answer gets misread.
    const comment = at < buf.length ? decoder.decode(readString()) : "";
    keys.push({ type: keyType(blob), address: ed25519Address(blob), comment });
  }
  return keys;
}

// Exported for the test, which parses captured bytes rather than talking to
// an agent: the shape of this message is the thing being pinned, and a live
// agent would change the fixture every time somebody's key did.
export { parseIdentities as parseIdentitiesForTest };

/** The algorithm an ssh wire-format key blob names, or "" when unreadable. */
function keyType(blob: Uint8Array): string {
  if (blob.length < 8) return "";
  const len = new DataView(blob.buffer, blob.byteOffset, blob.byteLength).getUint32(0, false);
  if (4 + len > blob.length) return "";
  return new TextDecoder().decode(blob.subarray(4, 4 + len));
}

/** The Solana account an ed25519 key blob names, or "" when it is not one. */
function ed25519Address(blob: Uint8Array): string {
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const algo = "ssh-ed25519";
  const need = 4 + algo.length + 4 + 32;
  if (blob.length !== need) return "";
  if (view.getUint32(0, false) !== algo.length) return "";
  if (new TextDecoder().decode(blob.subarray(4, 4 + algo.length)) !== algo) return "";
  if (view.getUint32(4 + algo.length, false) !== 32) return "";
  return encodeBase58(blob.subarray(need - 32));
}

async function writeFramed(conn: Deno.UnixConn, payload: Uint8Array): Promise<void> {
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, payload.length, false);
  await conn.write(header);
  await conn.write(payload);
}

async function readFramed(conn: Deno.UnixConn): Promise<Uint8Array | null> {
  // Read the 4-byte length header, then the body. readExactly is not in
  // Deno's stable Deno.UnixConn surface; loop on read() until either the
  // buffer is full or the connection closes.
  const header = new Uint8Array(4);
  let got = 0;
  while (got < 4) {
    const n = await conn.read(header.subarray(got));
    if (n === null) {
      if (got === 0) return null;
      throw new Error(`agent closed after ${got} header bytes`);
    }
    got += n;
  }
  const len = new DataView(header.buffer).getUint32(0, false);
  if (len > MAX_RESPONSE_BYTES) {
    throw new Error(`agent response is ${len} bytes, exceeds ${MAX_RESPONSE_BYTES}`);
  }
  const body = new Uint8Array(len);
  got = 0;
  while (got < len) {
    const n = await conn.read(body.subarray(got));
    if (n === null) {
      throw new Error(`agent closed after ${got}/${len} body bytes`);
    }
    got += n;
  }
  return body;
}