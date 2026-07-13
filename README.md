# mcp-oauth-gateway

A small reverse proxy that puts a **GitHub-bridged OAuth 2.1 authorization server**
in front of an **unauthenticated MCP server**, so AI clients that only accept
unprotected *or* OAuth-protected MCP servers (Claude, ChatGPT, …) can use it —
gated by an allowlist of GitHub user IDs.

Drop it into your compose stack in front of any HTTP/SSE MCP server; it needs no
changes to that server.

## How it works

The gateway is both OAuth roles at once, and uses GitHub only as the identity source:

- **Resource server** — validates bearer tokens, serves Protected Resource
  Metadata (RFC 9728), and answers unauthenticated requests with `401` +
  `WWW-Authenticate`.
- **Authorization server** — Dynamic Client Registration (RFC 7591), the PKCE
  authorization-code flow (`/authorize`, `/token`), and issues its **own** RS256
  JWTs whose audience is bound to the MCP endpoint (RFC 8707).

```
MCP client ──/mcp (401)──▶ gateway ──discovery──▶ /.well-known/*
           ──register/authorize/token──▶ gateway ──login──▶ GitHub
           ◀── gateway JWT ──                     (allowlist check on GitHub user id)
           ──/mcp + Bearer──▶ gateway ──validate + strip auth──▶ upstream MCP server
```

The gateway never forwards the client's token, cookies, or the GitHub token to
the upstream (no token passthrough).

## Quick start (local)

Requires Go 1.26.

1. Create a GitHub OAuth app at <https://github.com/settings/developers>:
   - Homepage URL: `http://localhost:8080`
   - Authorization callback URL: `http://localhost:8080/callback`
2. Write a config (`gateway.yaml`):
   ```yaml
   issuer: http://localhost:8080
   upstream: http://localhost:3001     # your MCP server's HTTP endpoint
   allowed_github_ids: [ 62141839 ]     # your GitHub numeric id
   key_path: ./keys/signing.pem
   ```
3. Run it:
   ```sh
   GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... \
     go run ./cmd/gateway -config gateway.yaml
   ```
4. Point a client at `http://localhost:8080/mcp`. The
   [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
   (`npx @modelcontextprotocol/inspector`) drives the whole DCR + OAuth flow.

Find your GitHub id: `curl https://api.github.com/users/<login>` → `"id"`.

## Deploy (compose)

See [`deploy/`](deploy). Copy the examples, fill them in, and bring it up:

```sh
cd deploy
cp gateway.example.yaml gateway.yaml     # issuer, allowed_github_ids, upstream
cp ../.env.example .env                   # GitHub OAuth app credentials
docker compose up -d                      # pulls ghcr.io/wampa04/mcp-oauth-gateway
```

By default this pulls the published image from GHCR (built and pushed by the
[`build`](.github/workflows/build.yml) workflow). To build from source instead:

```sh
docker compose -f docker-compose.yml -f local.compose.yaml up -d --build
```

The compose file terminates TLS at Traefik (labels on the gateway only) and keeps
the MCP server internal. For a quick test without Traefik, publish the port
directly (see the commented `ports:` block).

## Configuration

| Key | Env override | Default | Notes |
|-----|--------------|---------|-------|
| `issuer` | `ISSUER` | — | external base URL; https required (except localhost) |
| `mcp_path` | — | `/mcp` | path clients connect to; also the token audience |
| `upstream` | `UPSTREAM` | — | internal URL of the MCP server |
| `allowed_github_ids` | — | — | fail-closed; empty = nobody |
| `key_path` | `KEY_PATH` | `keys/signing.pem` | persist it, or restarts invalidate tokens |
| `token_ttl` | — | `1h` | access-token lifetime |
| `require_consent` | — | `true` | per-client consent screen before GitHub |
| `github.client_id` | `GITHUB_CLIENT_ID` | — | required |
| `github.client_secret` | `GITHUB_CLIENT_SECRET` | — | required |
| `tls.cert_file` / `tls.key_file` | — | — | optional built-in TLS (else run behind a proxy) |

## Security notes

- Tokens are RS256, signed with a persisted key exposed at
  `/.well-known/jwks.json`; validation pins the algorithm and enforces
  issuer, audience, and expiry.
- Access is fail-closed: the GitHub id is checked against the allowlist at both
  the callback and token issuance.
- PKCE (S256) is mandatory; auth codes are single-use with a short TTL; redirect
  URIs are matched exactly.
- In-memory client/consent/pending state is capped and rejected-when-full rather
  than evicting established registrations.