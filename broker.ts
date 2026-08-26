#!/usr/bin/env bun
/**
 * claude-peers broker daemon
 *
 * A singleton HTTP server on localhost:7899 backed by SQLite.
 * Tracks all registered Claude Code peers and routes messages between them.
 *
 * Auto-launched by the MCP server if not already running.
 * Run directly: bun broker.ts
 */

import { Database } from "bun:sqlite";
import { homedir } from "node:os";
import { join } from "node:path";
import { writeFileSync, chmodSync } from "node:fs";
import type {
  RegisterRequest,
  RegisterResponse,
  HeartbeatRequest,
  SetSummaryRequest,
  ListPeersRequest,
  SendMessageRequest,
  PollMessagesRequest,
  PollMessagesResponse,
  Peer,
  Message,
} from "./shared/types.ts";

const PORT = parseInt(process.env.CLAUDE_PEERS_PORT ?? "7899", 10);
// Use os.homedir() rather than process.env.HOME: HOME is undefined when the
// process is spawned natively on Windows (which uses USERPROFILE), and
// path.join produces the correct separator on every platform.
const DB_PATH = process.env.CLAUDE_PEERS_DB ?? join(homedir(), ".claude-peers.db");

// --- Database setup ---

// --- Shutdown authorization ---
//
// /shutdown terminates the broker, and the broker is the coordination channel
// for every peer on the machine. It had no authorization of any kind, so ANY
// local process could stop it — including a web page, since a browser can POST
// to 127.0.0.1 from any origin.
//
// The token is generated per broker start and written next to the database with
// owner-only permissions. That grants nothing new: anything able to read this
// file can already read the message database beside it. It only stops callers
// that cannot, which is the entire drive-by case.
const SHUTDOWN_TOKEN_PATH = `${DB_PATH}.shutdown-token`;
const SHUTDOWN_TOKEN = crypto.randomUUID();

const db = new Database(DB_PATH);
db.run("PRAGMA journal_mode = WAL");
db.run("PRAGMA busy_timeout = 3000");

db.run(`
  CREATE TABLE IF NOT EXISTS peers (
    id TEXT PRIMARY KEY,
    pid INTEGER NOT NULL,
    cwd TEXT NOT NULL,
    git_root TEXT,
    tty TEXT,
    summary TEXT NOT NULL DEFAULT '',
    registered_at TEXT NOT NULL,
    last_seen TEXT NOT NULL
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id TEXT NOT NULL,
    to_id TEXT NOT NULL,
    text TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (from_id) REFERENCES peers(id),
    FOREIGN KEY (to_id) REFERENCES peers(id)
  )
`);

// --- Indexes ---
//
// Without these, /poll-messages runs a full table scan plus a temp-B-tree sort
// against a table that only grows. Measured on a three-day-old database: 33ms
// per poll, 18 peers polling at 1Hz, ~59% of one core spent scanning — and the
// cost rises linearly with lifetime message history, so the broker got slower
// every day it ran until its event loop stalled and it started refusing
// connections. With the index the same poll is an index seek.
db.run(`
  CREATE INDEX IF NOT EXISTS idx_messages_to_delivered
    ON messages(to_id, delivered, sent_at)
`);
db.run(`CREATE INDEX IF NOT EXISTS idx_messages_delivered ON messages(delivered)`);

// --- Message retention ---

// 0 disables the sweep entirely.
const RETENTION_DAYS = parseInt(process.env.CLAUDE_PEERS_RETENTION_DAYS ?? "90", 10);

// Prune messages that have ALREADY been delivered and are older than the
// retention window.
//
// Only delivered rows. Deleting undelivered messages is what silently
// destroyed mail for peers that restarted before polling — the sender had
// already been told `{ ok: true }`. Indexes make polling cheap but do not bound
// the table, and it grew ~13MB of message text in its first month.
//
// julianday() on BOTH sides, deliberately. sent_at is stored as ISO-8601
// ("2026-08-20T23:55:10.611Z") while datetime('now', ...) yields
// "2026-08-20 23:55:40" — a space separator and no Z. Comparing those as
// strings puts 'T' (0x54) above ' ' (0x20), so every message sent on the
// boundary day is skipped. Measured against the live database at a 30-day
// window: the string form selected 23 rows, julianday selected 479.
function sweepOldMessages() {
  if (!Number.isFinite(RETENTION_DAYS) || RETENTION_DAYS <= 0) return;

  const result = db.run(
    `DELETE FROM messages
     WHERE delivered = 1
       AND julianday(sent_at) < julianday('now', '-' || ? || ' days')`,
    [RETENTION_DAYS]
  );

  if (result.changes > 0) {
    console.error(
      `[claude-peers broker] retention: pruned ${result.changes} delivered message(s) older than ${RETENTION_DAYS}d`
    );
  }
}

sweepOldMessages();
setInterval(sweepOldMessages, 60 * 60_000); // hourly

// Check whether a process is still alive. process.kill(pid, 0) sends no signal —
// it only probes existence. It throws ESRCH when the pid is truly gone, but EPERM
// when the process EXISTS and we merely lack permission to signal it (a peer owned
// by another user, or one running elevated while the broker is not). EPERM means
// alive, so treat ONLY ESRCH as dead — evicting a peer is destructive and should
// require positive proof of death. Same semantics on Windows, Linux, macOS, BSD.
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as { code?: string }).code !== "ESRCH";
  }
}

// Clean up stale peers (PIDs that no longer exist) on startup
function cleanStalePeers() {
  const peers = db.query("SELECT id, pid FROM peers").all() as { id: string; pid: number }[];
  for (const peer of peers) {
    if (!isProcessAlive(peer.pid)) {
      db.run("DELETE FROM peers WHERE id = ?", [peer.id]);
      // Deliberately do NOT delete this peer's undelivered messages.
      //
      // /send-message returns { ok: true } as soon as the row is inserted, so
      // the sender already holds positive evidence of success. Deleting here
      // destroys the message silently and the loss is undetectable from the
      // sender's side — an ack that does not mean delivery. That is the worst
      // shape a messaging failure can take, and it is invisible precisely
      // because nothing bounces.
      //
      // This was survivable while every peer was a long-lived Claude Code
      // session. It stops being survivable for process-per-task local agents,
      // which restart constantly: the workload that makes eviction common is
      // exactly the workload being added.
      //
      // Retaining the rows does not by itself deliver them — handleRegister
      // mints a fresh random id on re-registration, so a restarted peer comes
      // back under a different identity and never polls for these. The rows are
      // preserved as evidence rather than destroyed as garbage. Durable
      // identity is the actual fix, and is what FAM's `name@account` model
      // exists to provide.
    }
  }
}

cleanStalePeers();

// Periodically clean stale peers (every 30s)
setInterval(cleanStalePeers, 30_000);

// --- Prepared statements ---

const insertPeer = db.prepare(`
  INSERT INTO peers (id, pid, cwd, git_root, tty, summary, registered_at, last_seen)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const updateLastSeen = db.prepare(`
  UPDATE peers SET last_seen = ? WHERE id = ?
`);

const updateSummary = db.prepare(`
  UPDATE peers SET summary = ? WHERE id = ?
`);

const deletePeer = db.prepare(`
  DELETE FROM peers WHERE id = ?
`);

const selectAllPeers = db.prepare(`
  SELECT * FROM peers
`);

// On case-insensitive filesystems (Windows), two sessions in the same directory
// can report differently-cased paths (e.g. C:\Dev\App vs C:\dev\app) and would
// otherwise fail to discover each other under "directory"/"repo" scope. Match
// case-insensitively there. Gated on the broker's own platform: a blanket
// COLLATE NOCASE would wrongly conflate genuinely distinct paths on
// case-sensitive Linux/BSD (macOS resolves cwd casing itself, so it's unaffected).
const PATH_COLLATE = process.platform === "win32" ? "COLLATE NOCASE" : "";

const selectPeersByDirectory = db.prepare(`
  SELECT * FROM peers WHERE cwd = ? ${PATH_COLLATE}
`);

const selectPeersByGitRoot = db.prepare(`
  SELECT * FROM peers WHERE git_root = ? ${PATH_COLLATE}
`);

const insertMessage = db.prepare(`
  INSERT INTO messages (from_id, to_id, text, sent_at, delivered)
  VALUES (?, ?, ?, ?, 0)
`);

const selectUndelivered = db.prepare(`
  SELECT * FROM messages WHERE to_id = ? AND delivered = 0 ORDER BY sent_at ASC
`);

const markDelivered = db.prepare(`
  UPDATE messages SET delivered = 1 WHERE id = ?
`);

// --- Generate peer ID ---

function generateId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 8; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// --- Request handlers ---

function handleRegister(body: RegisterRequest): RegisterResponse {
  const id = generateId();
  const now = new Date().toISOString();

  // Remove any existing registration for this PID (re-registration)
  const existing = db.query("SELECT id FROM peers WHERE pid = ?").get(body.pid) as { id: string } | null;
  if (existing) {
    deletePeer.run(existing.id);
  }

  insertPeer.run(id, body.pid, body.cwd, body.git_root, body.tty, body.summary, now, now);
  return { id };
}

function handleHeartbeat(body: HeartbeatRequest): void {
  updateLastSeen.run(new Date().toISOString(), body.id);
}

function handleSetSummary(body: SetSummaryRequest): void {
  updateSummary.run(body.summary, body.id);
}

function handleListPeers(body: ListPeersRequest): Peer[] {
  let peers: Peer[];

  switch (body.scope) {
    case "machine":
      peers = selectAllPeers.all() as Peer[];
      break;
    case "directory":
      peers = selectPeersByDirectory.all(body.cwd) as Peer[];
      break;
    case "repo":
      if (body.git_root) {
        peers = selectPeersByGitRoot.all(body.git_root) as Peer[];
      } else {
        // No git root, fall back to directory
        peers = selectPeersByDirectory.all(body.cwd) as Peer[];
      }
      break;
    default:
      peers = selectAllPeers.all() as Peer[];
  }

  // Exclude the requesting peer
  if (body.exclude_id) {
    peers = peers.filter((p) => p.id !== body.exclude_id);
  }

  // Verify each peer's process is still alive (only truly-gone pids are evicted)
  return peers.filter((p) => {
    if (isProcessAlive(p.pid)) return true;
    // Clean up dead peer
    deletePeer.run(p.id);
    return false;
  });
}

function handleSendMessage(body: SendMessageRequest): { ok: boolean; error?: string } {
  // Verify target exists
  const target = db.query("SELECT id FROM peers WHERE id = ?").get(body.to_id) as { id: string } | null;
  if (!target) {
    return { ok: false, error: `Peer ${body.to_id} not found` };
  }

  insertMessage.run(body.from_id, body.to_id, body.text, new Date().toISOString());
  return { ok: true };
}

function handlePollMessages(body: PollMessagesRequest): PollMessagesResponse {
  const messages = selectUndelivered.all(body.id) as Message[];

  // Mark them as delivered
  for (const msg of messages) {
    markDelivered.run(msg.id);
  }

  return { messages };
}

function handleUnregister(body: { id: string }): void {
  deletePeer.run(body.id);
}

function handleShutdown(): void {
  // Exit shortly after so the HTTP response flushes to the caller first.
  // This replaces the previous lsof/kill approach, which only worked on Unix.
  setTimeout(() => process.exit(0), 100);
}

// --- HTTP Server ---

try {
  Bun.serve({
    port: PORT,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);
      const path = url.pathname;

      if (req.method !== "POST") {
        if (path === "/health") {
          return Response.json({ status: "ok", peers: (selectAllPeers.all() as Peer[]).length });
        }
        return new Response("claude-peers broker", { status: 200 });
      }

      try {
        const body = await req.json();

        switch (path) {
          case "/register":
            return Response.json(handleRegister(body as RegisterRequest));
          case "/heartbeat":
            handleHeartbeat(body as HeartbeatRequest);
            return Response.json({ ok: true });
          case "/set-summary":
            handleSetSummary(body as SetSummaryRequest);
            return Response.json({ ok: true });
          case "/list-peers":
            return Response.json(handleListPeers(body as ListPeersRequest));
          case "/send-message":
            return Response.json(handleSendMessage(body as SendMessageRequest));
          case "/poll-messages":
            return Response.json(handlePollMessages(body as PollMessagesRequest));
          case "/unregister":
            handleUnregister(body as { id: string });
            return Response.json({ ok: true });
          case "/shutdown": {
            const token = (body as { token?: string })?.token;
            if (!token || token !== SHUTDOWN_TOKEN) {
              return Response.json(
                { error: "unauthorized: /shutdown requires the token from " + SHUTDOWN_TOKEN_PATH },
                { status: 401 }
              );
            }
            handleShutdown();
            return Response.json({ ok: true });
          }
          default:
            return Response.json({ error: "not found" }, { status: 404 });
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return Response.json({ error: msg }, { status: 500 });
      }
    },
  });
} catch (e) {
  // Another broker won the port — a TOCTOU race when several sessions start at
  // once (each sees no broker and spawns one). That broker is the singleton, so
  // exit quietly with code 0 rather than crashing with a stack trace. Same
  // EADDRINUSE behavior on Windows, Linux, macOS, and BSD.
  if ((e as { code?: string }).code === "EADDRINUSE") {
    console.error(`[claude-peers broker] port ${PORT} already in use — another broker is running`);
    process.exit(0);
  }
  throw e;
}

// Written only once the server is actually listening, so the file's presence
// means a live broker rather than an attempted one.
writeFileSync(SHUTDOWN_TOKEN_PATH, SHUTDOWN_TOKEN, { mode: 0o600 });
// `mode` on writeFileSync only applies when the file is CREATED; an existing
// file keeps whatever mode it had. chmod unconditionally.
try { chmodSync(SHUTDOWN_TOKEN_PATH, 0o600); } catch {}

console.error(`[claude-peers broker] listening on 127.0.0.1:${PORT} (db: ${DB_PATH})`);
