/**
 * FAM — Federated Agent Messaging
 *
 * Agent-framework-agnostic messaging for agents, humans, and tools.
 *
 * Entry points:
 *   - src/server/http.ts          — FAM server (HTTP + WebSocket)
 *   - src/adapters/mcp/server.ts  — FAM MCP adapter (one per agent instance)
 *   - src/adapters/cli/main.ts    — FAM CLI
 *
 * The legacy claude-peers entry points are retained alongside during the
 * transition and are what currently carries real traffic:
 *   - server.ts  — claude-peers MCP server
 *   - broker.ts  — claude-peers broker daemon
 *
 * See README.md for setup, DESIGN.md for architecture, ROADMAP.md for status.
 */

export {}; // module marker
