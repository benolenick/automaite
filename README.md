# Automaite Terminal

Control your AI agents (Claude Code, Gemini CLI, Codex) from your phone or browser.

## Architecture

```
Browser / Android app
        │
        │ WSS (term.automaite.ca)
        ▼
   Relay server (FastAPI)       ← pure WebSocket relay, no AI runs here
        │
        │ WSS (localhost)
        ▼
  Desktop agent (automaite.exe) ← runs on YOUR computer
        │
        │ PTY
        ▼
  Claude / Gemini / Codex       ← your AI, your API keys, your machine
```

- **Relay** (`relay/`) — FastAPI WebSocket relay. Handles auth (Google OAuth), subscriptions (Stripe), session routing, and the optional credential vault.
- **Desktop agent** (`desktop/`) — Windows tray app. Connects to relay, spawns PTY sessions locally.
- **Android app** (`android/`) — Kotlin WebView app with deep-link auth and biometric vault.
- **Agent** (`agent/`) — Linux PTY agent (for self-hosted deployments).
- **Site** (`site/`) — automaite.ca marketing site.

## Self-hosting

```bash
cp .env.example .env
# fill in GOOGLE_CLIENT_ID, TERMINAL_JWT_SECRET, TERMINAL_AGENT_KEY, Stripe keys
docker compose up -d
```

## Security

See [automaite.ca/security](https://automaite.ca/security) for a full breakdown of the security model.

## License

Coming soon — planned open source release.
