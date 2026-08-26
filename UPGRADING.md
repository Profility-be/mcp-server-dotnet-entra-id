# Upgrading

This template was modernized from **.NET 8 + MCP C# SDK 0.4.0-preview.2** to **.NET 10 + MCP C# SDK 2.2.0**.

If you cloned this repository before that change, read this page before you merge. The good news
first: the SDK's public API did not change, so `AddMcpServer()`, `WithHttpTransport()`,
`WithToolsFromAssembly()`, `MapMcp()`, `[McpServerToolType]` and `[McpServerTool]` all still compile
untouched. **The upgrade builds clean with zero warnings.** What changed is *behaviour* — and one of
those changes is visible to your clients.

---

## The one that will bite you: tool names

The SDK derives a tool's wire name from the method name as **lower snake_case** (stripping a
trailing `Async`). The example tool is therefore now advertised as `who_am_i`, not `WhoAmI`.

If anything on your side pins tool names — a prompt, a test, an allow-list, a client config — check
them. To keep an old name, set it explicitly:

```csharp
[McpServerTool(Name = "WhoAmI")]
public WhoAmIResult WhoAmI(RequestContext<CallToolRequestParams> context) { ... }
```

---

## Streamable HTTP is now stateless by default

SDK 2.0 made `HttpServerTransportOptions.SessionMode` default to `Stateless`, following protocol
revision `2026-07-28` (SEP-2567), which removed `Mcp-Session-Id` from the spec. This template keeps
that default because it is what a server built today should do.

What stateless means in practice:

| | Stateless (default) |
|---|---|
| `Mcp-Session-Id` | not issued, ignored on requests |
| Session affinity | not needed — scale out freely |
| `GET` / `DELETE` on the MCP route | unavailable |
| `/sse` and `/message` | not mapped |
| Sampling, elicitation, roots | **unavailable** — the server cannot make requests to the client |

That last row is the one to check. If one of your tools calls `ElicitAsync` or `SampleAsync`, it
stops working in stateless mode. The replacement on `2026-07-28` is
[MRTR](https://csharp.sdk.modelcontextprotocol.io/concepts/mrtr); until you migrate, use a stateful
session mode.

**Existing clients mostly keep working.** A down-level client that sends the classic `initialize`
handshake is still answered correctly in stateless mode — it simply gets no session back. This was
verified against protocol revision `2025-11-25`.

### Restoring the old behaviour

No code change needed. Both knobs live in `appsettings.json` under the existing `MCP` section:

```jsonc
"MCP": {
  "ServerUrl": "https://your-server-url.azurewebsites.net",
  "SessionMode": "Stateless",   // Stateless | StatefulForInitializeClients | Stateful
  "EnableLegacySse": false
}
```

| `SessionMode` | Use when |
|---|---|
| `Stateless` | **Default.** New deployments, and anything that needs to scale out without affinity. |
| `StatefulForInitializeClients` | You have a mixed client fleet. Older `initialize`-handshake clients get a real session; `2026-07-28`-and-later clients are served statelessly on the same endpoint. Requires session affinity. |
| `Stateful` | Closest to the pre-2.0 behaviour. Note that modern clients are forced to downgrade to the handshake. |

`EnableLegacySse` maps the deprecated `/sse` and `/message` endpoints (protocol `2024-11-05`) and
requires a stateful `SessionMode`. It is off by default for a reason: legacy SSE returns
`202 Accepted` immediately, so there is no HTTP-level backpressure on handler concurrency. The SDK
marks the property `[Obsolete]` (diagnostic `MCP9004`); `Program.cs` only touches it when you opt in,
so a default build stays warning-free.

---

## Protected resource metadata moved into the SDK

`/.well-known/oauth-protected-resource` (RFC 9728) used to be a hand-written action in
`WellKnownController`. It is now configured once in `Program.cs` via
`McpAuthenticationOptions.ResourceMetadata` and served by the SDK.

This is not just tidying. The SDK's authentication scheme also emits the matching challenge header,
which the controller never did:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://your-server/.well-known/oauth-protected-resource"
```

That header is how an MCP client discovers your authorization server instead of guessing. The wiring
that makes it work:

```csharp
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = McpAuthenticationDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(...)
    .AddMcp(options => { options.ResourceMetadata = new() { ... }; });
```

`ResourceMetadataUri` is deliberately left at its default, so the handler serves *and* advertises the
document relative to the incoming request. Resist the temptation to pin it to your public URL: the
handler matches incoming requests against that value, so an absolute URI on a different host than the
request makes the document itself return **404** while the challenge header still advertises it. If a
reverse proxy rewrites the `Host` header, configure
[forwarded headers](https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer)
rather than overriding this option.

**If you customised that controller action**, move your changes into the `ResourceMetadata` object.
The authorization-server metadata (`/.well-known/oauth-authorization-server`, RFC 8414) is still
hand-written, because this proxy *is* the authorization server and the SDK does not model that side.

Also new: the CORS policy exposes `WWW-Authenticate`. A browser-based MCP client cannot read the
challenge — and therefore cannot discover the authorization server — unless that header is exposed.

---

## Read the user from `RequestContext`, not `IHttpContextAccessor`

`WhoAmITool` used to take an `IHttpContextAccessor` and read `HttpContext.User`. It now takes a
`RequestContext<CallToolRequestParams>` and reads `context.User`:

```csharp
public WhoAmIResult WhoAmI(RequestContext<CallToolRequestParams> context)
{
    var user = context.User;   // ClaimsPrincipal, inherited from MessageContext
    ...
}
```

`RequestContext.User` is transport-agnostic and correct in every session mode. `IHttpContextAccessor`
happens to work in stateless mode, but in a stateful session the tool runs outside the HTTP request
that created the session, so the `HttpContext` is gone.

`AddHttpContextAccessor()` is still registered, so your own tools that depend on it keep working.
Migrate them when convenient.

---

## Tool metadata and structured output

The example tool now declares annotations and returns a typed record instead of a formatted string:

```csharp
[McpServerTool(Title = "Who am I?", ReadOnly = true, Idempotent = true,
               OpenWorld = false, UseStructuredContent = true)]
```

The annotations tell a client the tool is safe to call without a confirmation prompt. Returning a
record makes the SDK publish an `outputSchema` and emit `structuredContent` alongside the text, so
clients consume fields instead of parsing prose.

If you had code reading the old emoji-formatted string, switch to the structured fields.

Note a related 2.0 change: a **non-object** return value is now emitted directly as structured
content (`72` rather than `{"result": 72}`).

---

## Other SDK 2.x notes

- **Roots, sampling and logging are deprecated** (`MCP9005`) per protocol `2026-07-28`. This template
  uses none of them.
- **Tasks moved** to the separate `ModelContextProtocol.Extensions.Tasks` package. Not used here.
- **OAuth conformance tightened.** Issuer validation per RFC 9207/8414 is mandatory and mismatches
  are rejected, so `MCP:ServerUrl` must match your discovery URL byte for byte — `AppConfiguration`
  strips trailing slashes to keep issuer, audience and resource identifier identical. PKCE metadata
  must advertise `S256` (it does), and dynamic client registration now sends an `application_type`
  field, which the registration endpoint ignores harmlessly.
- **New and worth knowing:** `AddAuthorizationFilters()` (now wired up) honours `[Authorize]` on
  individual tools and filters `tools/list` per user; call-tool filters are a clean home for audit
  logging; `WithDistributedCacheEventStreamStore` adds SSE resumability.

---

## .NET 10

The target framework is now `net10.0` (LTS, supported until November 2028). .NET 8 goes out of
support on **10 November 2026**.

Make sure your host runs .NET 10 — on Azure App Service, check the runtime stack setting. The MCP SDK
itself still supports `net8.0` and `net9.0`, so if you are pinned to an older runtime you can lower
the single `<TargetFramework>` value in `MCP/MCP.csproj` and drop the `net10.0` package versions back
to a matching major.

### Package changes

| Package | From | To |
|---|---|---|
| `ModelContextProtocol.AspNetCore` | 0.4.0-preview.2 | 2.2.0 |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 8.0.11 | 10.0.11 |
| `Microsoft.IdentityModel.Tokens` | 8.2.1 | 8.22.0 |
| `System.IdentityModel.Tokens.Jwt` | 8.2.1 | 8.22.0 |
| `Azure.Data.Tables` | 12.11.0 | 12.12.0 |
| `Microsoft.Extensions.Caching.Memory` | 8.0.1 | *removed* — part of the ASP.NET Core shared framework |

---

## What deliberately did **not** change

So that a `git pull` stays survivable:

- **No configuration key was renamed.** `MCP:ServerUrl`, `AzureAd:*`, `Jwt:*`, `TokenStore:*` and
  `OAuth:*` all keep their names and meaning. `MCP:SessionMode` and `MCP:EnableLegacySse` are new
  additions with safe defaults.
- **No extension point changed signature.** `IClaimProvider`, `ITokenStore`, `ILoginTokenStore`,
  `IClientStore`, `IJwtBuilder` and `IBrandingProvider` are untouched, so your own implementations
  still compile.
- **The OAuth proxy flow is unchanged.** `/oauth/register`, `/oauth/authorize`, `/oauth/continue`,
  `/oauth/cancel`, `/oauth/callback`, `/oauth/token` and the login UI behave exactly as before.
- **`/health` and `/.well-known/oauth-authorization-server` are unchanged.**

---

## Verifying your own upgrade

With the server running, these four probes cover the changes above:

```bash
# 1. The challenge now advertises the metadata document
curl -sk -X POST https://localhost:5248/ -D - -o /dev/null | grep -i www-authenticate

# 2. The metadata document itself
curl -sk https://localhost:5248/.well-known/oauth-protected-resource

# 3. /sse is gone unless you opted in
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:5248/sse    # 404

# 4. Tool names and schemas, with a valid bearer token.
#    Protocol 2026-07-28 requires the Mcp-Method header plus per-request _meta.
curl -sk -X POST https://localhost:5248/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/list" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{},
        "io.modelcontextprotocol/clientInfo":{"name":"probe","version":"1.0"}}}}'
```

The startup log states the active mode, which is the quickest sanity check of all:

```
info: MCP[0] MCP session mode: Stateless (legacy SSE: False)
```

---

## References

- [MCP C# SDK releases](https://github.com/modelcontextprotocol/csharp-sdk/releases) — the
  [v2.0.0 notes](https://github.com/modelcontextprotocol/csharp-sdk/releases/tag/v2.0.0) list every
  breaking change with its diagnostic ID
- [MCP C# SDK documentation](https://csharp.sdk.modelcontextprotocol.io/)
- [List of SDK diagnostics](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/docs/list-of-diagnostics.md)
  (`MCP9004`, `MCP9005`, …)
- [.NET support policy](https://dotnet.microsoft.com/platform/support/policy/dotnet-core)
