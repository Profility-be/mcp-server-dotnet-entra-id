# MCP OAuth Proxy - Technical Architecture

**Deep dive into the OAuth 2.1 proxy architecture for Claude AI and Microsoft Entra ID integration.**

**Built with**: [Model Context Protocol C# SDK](https://github.com/modelcontextprotocol/csharp-sdk)

---

## Important Notes

### MCP C# SDK

This project leverages the **official Model Context Protocol C# SDK** from Anthropic. This SDK provides:

- ✅ **Strongly-typed MCP protocol implementation**
- ✅ **Automatic request/response serialization**
- ✅ **Built-in error handling**
- ✅ **Tool registration and discovery**
- ✅ **OAuth flow helpers**

**Why this matters**: Before discovering this SDK, implementing MCP required manual protocol handling and JSON serialization. The SDK dramatically simplified development and reduced boilerplate code.

**GitHub**: https://github.com/modelcontextprotocol/csharp-sdk

### Production Storage Warning

⚠️ **This implementation uses in-memory storage for simplicity**:

- `ConcurrentDictionary` (static) for PKCE state, token mappings, client registrations and login tokens

**Why this is only for development/demos**:
- ❌ Data is lost on application restart
- ❌ Does not work with multiple instances (web farms)
- ❌ No persistence or audit trail
- ❌ Limited scalability

**For production, replace with**:
- ✅ **Azure Table Storage** (included) - Both TokenStore and ClientStore support this
- ✅ **Redis** (recommended for high-performance) - Distributed cache, fast, scales horizontally
- ✅ **SQL Server** - Persistent, supports transactions and audit trail

See [Persistent Storage Recommendations](#persistent-token-storage-recommendations) below for details.

---

## Table of Contents

1. [Claude's MCP OAuth Discovery Flow](#claudes-mcp-oauth-discovery-flow)
2. [RFC 8707 Resource Indicators Implementation](#rfc-8707-resource-indicators-implementation)
3. [Dual PKCE Implementation](#dual-pkce-implementation)
4. [Token Mapping Strategy](#token-mapping-strategy)
5. [Custom Login Page Flow](#custom-login-page-flow)
6. [Security Architecture](#security-architecture)

---

## Claude's MCP OAuth Discovery Flow

### Discovery Sequence

When Claude connects to an MCP server, it follows this discovery process:

```
1. User configures MCP server URL in Claude
   └─> https://your-mcp-server.com/

2. Claude fetches Protected Resource Metadata
   └─> GET /.well-known/oauth-protected-resource
   └─> Response:
       {
         "resource": "https://your-mcp-server.com/",
         "authorization_servers": ["https://your-mcp-server.com/oauth"],
         "scopes_supported": ["api://YOUR-CLIENT-ID/MCP.Access"],
         "bearer_methods_supported": ["header"]
       }

3. Claude fetches Authorization Server Metadata
   └─> GET https://your-mcp-server.com/oauth/.well-known/oauth-authorization-server
   └─> Extracts endpoints:
       - authorization_endpoint
       - token_endpoint
       - registration_endpoint

4. Claude attempts Dynamic Client Registration
   └─> POST {registration_endpoint}
   └─> Body: {
         "client_name": "claudeai",
         "grant_types": ["authorization_code", "refresh_token"],
         "response_types": ["code"],
         "token_endpoint_auth_method": "none",
         "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
       }
```

### Authorization Request Parameters

Claude sends these exact parameters:

```
GET {authorization_endpoint}?
  response_type=code
  &client_id={dynamically_registered_client_id}
  &redirect_uri=https://claude.ai/api/mcp/auth_callback
  &code_challenge={calculated_sha256_hash}
  &code_challenge_method=S256
  &state={random_csrf_token}
  &scope={requested_scopes}
  &resource={mcp_server_url}  ← RFC 8707 Resource Indicator
```

**Key Points:**
- Claude generates `code_challenge` client-side with SHA-256
- `state` parameter provides CSRF protection
- `resource` parameter specifies token audience (RFC 8707)

### Token Exchange Request

After receiving authorization code:

```http
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={authorization_code}
&redirect_uri=https://claude.ai/api/mcp/auth_callback
&client_id={client_id}
&code_verifier={original_random_string}
&resource={mcp_server_url}
```

---

## RFC 8707 Resource Indicators Implementation

### The Entra ID Challenge

RFC 8707 defines the `resource` parameter for specifying token audience, but **Microsoft Entra ID does not implement this specification**.

**The Problem:**

```csharp
// Entra ID IGNORES the resource parameter
var authUrl = $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?" +
    $"client_id={clientId}" +
    $"&response_type=code" +
    $"&redirect_uri={redirectUri}" +
    $"&resource=https://your-mcp-server.com/";  // ← Ignored by Entra ID
```

MCP spec requires:
1. Clients send `resource` parameter
2. Tokens contain `aud` (audience) claim matching **exactly** the MCP server URI
3. MCP servers reject tokens if `aud` doesn't match

Entra ID tokens have `aud` set to `api://{clientId}`, **NOT** the MCP server URL.

### Workaround: Scope-Based Audience

Since Entra ID doesn't support `resource`, we use scopes to identify the audience:

```csharp
// In Azure App Registration
// Expose an API > Add a scope:
// Scope name: MCP.Access
// This creates: api://{clientId}/MCP.Access

// In authorization request
var authUrl = $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?" +
    $"client_id={clientId}" +
    $"&response_type=code" +
    $"&redirect_uri={proxyRedirectUri}" +
    $"&scope=api://{entraClientId}/MCP.Access openid profile email";
```

### Proxy Token Generation

The proxy generates JWT tokens with the correct `aud` claim:

```csharp
public string GenerateToken(string subject, string audience, string[] scopes)
{
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, subject),
        new Claim(JwtRegisteredClaimNames.Aud, audience),  // ← MCP server URL
        new Claim(JwtRegisteredClaimNames.Iss, proxyUrl),
        new Claim(JwtRegisteredClaimNames.Iat, 
            new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString()),
        new Claim("scope", string.Join(" ", scopes))
    };
    
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
            signingKey, 
            SecurityAlgorithms.RsaSha256)
    };
    
    return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
}
```

---

## Dual PKCE Implementation

### Why Dual PKCE?

The proxy sits between Claude and Entra ID, creating **two separate OAuth flows**:

1. **Claude ↔ Proxy**: Claude generates code_challenge, proxy must validate it
2. **Proxy ↔ Entra ID**: Proxy generates its own code_challenge for Entra ID

```
┌─────────┐ PKCE Flow 1 ┌──────────┐ PKCE Flow 2 ┌────────────┐
│ Claude  ├────────────►│  Proxy   ├────────────►│ Entra ID   │
└─────────┘             └──────────┘             └────────────┘
  code_                   code_                    code_
  challenge_1             challenge_2              challenge_2
  code_                   code_                    code_
  verifier_1              verifier_2               verifier_2
```

### PKCE State Data Model

```csharp
public class PkceStateData
{
    // Claude's PKCE parameters (Flow 1)
    public string CodeChallenge { get; set; } = default!;
    public string CodeChallengeMethod { get; set; } = "S256";
    
    // Proxy's PKCE parameters (Flow 2)
    public string ProxyCodeVerifier { get; set; } = default!;
    public string ProxyCodeChallenge { get; set; } = default!;
    
    // OAuth flow parameters
    public string OriginalRedirectUri { get; set; } = default!;
    public string ProxyClientId { get; set; } = default!;
    public string RequestedScopes { get; set; } = default!;
    public string RequestedResource { get; set; } = default!;
    public string CsrfToken { get; set; } = default!;
    public DateTime CreatedAt { get; set; }
}
```

### PKCE Code Generation

```csharp
public static class PkceValidator
{
    public static string GenerateCodeVerifier()
    {
        // RFC 7636: 43-128 characters, [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        var bytes = new byte[32];  // 32 bytes = 43 base64url characters
        RandomNumberGenerator.Fill(bytes);
        
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
    
    public static string CalculateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        
        return Convert.ToBase64String(hash)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
    
    public static bool ValidateChallenge(
        string codeVerifier, 
        string codeChallenge, 
        string codeChallengeMethod)
    {
        if (codeChallengeMethod == "S256")
        {
            var calculatedChallenge = CalculateCodeChallenge(codeVerifier);
            return calculatedChallenge == codeChallenge;
        }
        return false;
    }
}
```

### Encrypted State Management

The proxy uses ASP.NET Core Data Protection to encrypt state containing PKCE parameters. The full implementation lives in `MCP/Services/PkceStateManager.cs` — it serializes the `PkceStateData`, protects it using IDataProtector and encodes the result as a URL-safe base64 string. See the source for encryption/decryption helpers and error handling.

Source: `MCP/Services/PkceStateManager.cs`
```csharp
// See the source file for the full implementation
```
        {
            var paddedState = state.Replace('-', '+').Replace('_', '/');
            paddedState = paddedState.PadRight(
                paddedState.Length + (4 - paddedState.Length % 4) % 4, 
                '=');
            var bytes = Convert.FromBase64String(paddedState);
            var encrypted = Encoding.UTF8.GetString(bytes);
            var json = _protector.Unprotect(encrypted);
            
            return JsonSerializer.Deserialize<PkceStateData>(json);
        }
        catch (CryptographicException)
        {
            return null;  // State was tampered with or expired
        }
    }
}
```

---

## Token Mapping Strategy

### Phantom Token Pattern

The proxy uses the **Phantom Token Pattern** to separate external and internal tokens:

```
┌─────────┐                    ┌──────────────┐                   ┌────────────┐
│ Claude  │ Opaque token       │ OAuth Proxy  │ JWT with claims   │ MCP Server │
│ Client  ├───────────────────>│   Gateway    ├──────────────────>│  Backend   │
└─────────┘                    └──────────────┘                   └────────────┘
             "abc123xyz..."         │                  JWT:
                                   │                  - aud: https://mcp-server
                                   │                  - sub: user@example.com
                                   │                  - scopes: ["MCP.Access"]
                                   │
                                   v
                          ┌───────────────────┐
                          │  Token Store      │
                          │  (In-memory store / ConcurrentDictionary)
                          │                   │
                          │  Mapping:         │
                          │  opaque → JWT     │
                          │  opaque → Entra   │
                          └───────────────────┘
```

### Token model (TokenData)

The project now uses a unified `TokenData` model that contains the Entra refresh token, user claims and PKCE state. This replaces older `TokenMapping` usage and consolidates authorization_code and refresh_token flows.

Key fields:
- Code (opaque proxy code / refresh token)
- EntraRefreshToken
- UserClaims (name, email, oid, upn, etc.)
- PkceState (original PKCE details)
- CreatedAt / ExpiresAt

### Token Store Interface

```csharp
public interface ITokenStore
{
    Task StoreCodeData(TokenData codeData);
    Task<TokenData?> GetAndConsumeCode(string code);
}
```

### In-memory Implementation (development)

For the reference implementation we use a static `ConcurrentDictionary<string, TokenData>` to store tokens in-memory. This keeps the API simple and provides atomic GET+REMOVE semantics for single-use tokens. **For production you should replace this with a persistent store (Redis/SQL).**

See the full implementation in `MCP/Services/InMemoryTokenStore.cs` for details and TTL handling.

```csharp
// See MCP/Services/InMemoryTokenStore.cs
```

---

## JWT Token Customization

### Claim Provider System

The proxy implements an extensible claim provider system that allows customization of JWT tokens issued to Claude. This enables adding organization-specific or application-specific claims beyond the standard Entra ID user information.

### Architecture

```csharp
public interface IClaimProvider
{
    void AddClaims(List<Claim> claims, ClaimProviderContext context);
}
```

**Key Features:**
- **Chaining**: Providers execute in registration order, allowing later providers to build on claims from earlier ones
- **Fail-safe**: If a provider fails, execution continues with remaining providers
- **Context-aware**: Providers receive relevant context including Entra ID user claims, client info, and scopes

### Default Claim Provider

The `DefaultClaimProvider` adds standard Entra ID claims to every JWT token:

### Custom Claim Providers

Organizations can implement custom claim providers for additional claims:

```csharp
public class CustomClaimProvider : IClaimProvider
{
    public void AddClaims(List<Claim> claims, ClaimProviderContext context)
    {
        // Add organization-specific claims
        claims.Add(new Claim("department", GetUserDepartment(context.UserIdentifier)));
        claims.Add(new Claim("cost_center", GetUserCostCenter(context.UserIdentifier)));
        claims.Add(new Claim("employee_id", GetEmployeeId(context.UserIdentifier)));
        
        // Conditional claims based on scopes
        if (context.Scopes.Contains("admin"))
        {
            claims.Add(new Claim("role", "administrator"));
        }
    }
}
```

See `MCP/Services/Jwt/SampleClaimProvider.cs` for a complete working example that demonstrates how to add custom claims to JWT tokens.

### Registration

Claim providers are registered as services in `Program.cs`:

```csharp
// Register claim providers (executed in registration order)
builder.Services.AddSingleton<IClaimProvider, DefaultClaimProvider>();  // Always first
builder.Services.AddSingleton<IClaimProvider, CustomClaimProvider>();   // Your custom provider
builder.Services.AddSingleton<IClaimProvider, AnotherProvider>();      // Additional providers
```

### Use Cases

**Enterprise Scenarios:**
- **Department/Roles**: Add organizational hierarchy claims
- **Cost Centers**: Include financial attribution data
- **Compliance**: Add audit-required claims (GDPR, SOX, etc.)
- **Application-specific**: Custom claims for specific MCP tools

**Security Considerations:**
- Claims are included in JWT tokens sent to Claude
- Ensure sensitive information is not exposed inappropriately
- Consider token size limits (JWTs should remain reasonably small)
- Validate claim values to prevent injection attacks


---

## Custom Login Page Flow

### Why an Intermediate Page?

The custom login page serves multiple purposes:

1. **Branding** - Maintain UX consistency with your organization
2. **User Education** - Explain what's happening before redirecting to Entra ID
3. **Consent** - Show requested permissions clearly
4. **Terms Acceptance** - Legal requirements can be displayed
5. **Language Localization** - Support for non-English users

### Implementation Details

The `/oauth/authorize` endpoint **directly renders** the login view (no redirect):

```csharp
[HttpGet("authorize")]
public async Task<IActionResult> Authorize(...)
{
    // ... validation and state management ...
    
    // CRITICAL: Render the view DIRECTLY (no redirect!)
    // Claude opens /oauth/authorize in a browser window
    // and expects to see HTML immediately, not a 302 redirect.
    var model = new LoginPageModel
    {
        LoginToken = loginToken,
        IsExpired = false,
        CompanyName = branding.CompanyName,
        ProductName = branding.ProductName,
        // ... branding colors ...
    };
    
    return View("~/Views/Login/Index.cshtml", model);
}
```

**Why no redirect?** Claude opens the authorization URL in a browser and expects immediate HTML content. A redirect would break this flow.

### Flow Sequence

```
┌─────────┐          ┌─────────────┐          ┌──────────────┐          ┌──────────┐
│ Claude  │          │   Browser   │          │ OAuth Proxy  │          │ Entra ID │
└────┬────┘          └──────┬──────┘          └──────┬───────┘          └────┬─────┘
     │                      │                        │                        │
     │ Opens auth URL       │                        │                        │
     │─────────────────────>│                        │                        │
     │                      │                        │                        │
     │                      │ GET /oauth/authorize   │                        │
     │                      │───────────────────────>│                        │
     │                      │                        │                        │
     │                      │ 200 OK (HTML page)     │                        │
     │                      │ [Continue] [Cancel]    │                        │
     │                      │<───────────────────────┤                        │
     │                      │                        │                        │
     │                      │ [User clicks Continue] │                        │
     │                      │                        │                        │
     │                      │ POST /oauth/continue   │                        │
     │                      │───────────────────────>│                        │
     │                      │                        │                        │
     │                      │           302 Redirect to Entra                 │
     │                      │<───────────────────────┤───────────────────────>│
     │                      │                        │                        │
     │                      │                        │   [User authenticates] │
     │                      │                        │                        │
     │                      │           302 Redirect with code                │
     │                      │           /oauth/callback?code=ABC              │
     │                      │<───────────────────────┤<───────────────────────┤
     │                      │                        │                        │
     │                      │                        │ POST token exchange    │
     │                      │                        │ (code + client secret) │
     │                      │                        │───────────────────────>│
     │                      │                        │                        │
     │                      │                        │ 200 OK                 │
     │                      │                        │ access_token + id_token│
     │                      │                        │ (with user claims)     │
     │                      │                        │<───────────────────────┤
     │                      │                        │                        │
     │                      │ 302 Redirect to Claude │                        │
     │                      │ with proxy auth code   │                        │
     │<─────────────────────┤<───────────────────────┤                        │
     │                      │                        │                        │
     │ POST /oauth/token                             │                        │
     │ (code_verifier + proxy auth code)             │                        │
     │──────────────────────┼───────────────────────>│                        │
     │                      │                        │                        │
     │ 200 OK - JWT access_token                     │                        │
     │ (signed by proxy, with user claims)           │                        │
     │<─────────────────────┼────────────────────────┤                        │
     │                      │                        │                        │
     │ GET /mcp/v1/tools                             │                        │
     │ Authorization: Bearer <JWT_token>             │                        │
     │──────────────────────┼───────────────────────>│                        │
     │                      │                        │                        │
     │                      │      (Proxy validates JWT signature             │
     │                      │       and extracts user claims)                 │
     │                      │                        │                        │
     │ 200 OK - MCP tools response                   │                        │
     │<─────────────────────┼────────────────────────┤                        │
```

### Login Token Model

The login token is used to track the state between the initial authorize request and the user's continue/cancel action:

```csharp
public class LoginTokenData
{
    public string EncryptedState { get; set; } = default!;
    public DateTime ExpiresAt { get; set; }
}
```

**Flow:**
1. `/oauth/authorize` creates a login token and embeds it in the form
2. User sees the login page and clicks "Continue" or "Cancel"
3. Form POSTs to `/oauth/continue` or `/oauth/cancel` with the token
4. Token is validated and marked as used (single-use only)

### Security Considerations

**Critical security points:**

1. **Single-use tokens**:
```csharp
public async Task<LoginTokenData?> GetAsync(string token)
{
    // Implementation uses a ConcurrentDictionary with TryRemove to ensure single-use semantics
    if (!_loginTokens.TryRemove(token, out var data)) { return null; }
    if (data.ExpiresAt < DateTime.UtcNow) { return null; }
    return data;
}
```

2. **Short TTL** (5 minutes maximum):
```csharp
ExpiresAt = DateTime.UtcNow.AddMinutes(5)
```

3. **Anti-CSRF tokens** in forms:
```cshtml
@Html.AntiForgeryToken()
```

4. **HTTPS enforcement**:
```csharp
app.UseHttpsRedirection();
app.UseHsts();
```

---

## Security Architecture

### Defense in Depth

The proxy implements multiple security layers:

```
Layer 1: HTTPS/TLS
  ↓
Layer 2: CORS (claude.ai only)
  ↓
Layer 3: PKCE validation
  ↓
Layer 4: Encrypted state (AES-256)
  ↓
Layer 5: Single-use codes
  ↓
Layer 6: Token expiration (1 hour)
  ↓
Layer 7: JWT signature validation
  ↓
Layer 8: Audience claim validation
```

### Token Lifecycle

```
1. Authorization Code
   - Single use
   - 5-minute lifetime
   - Stored in memory cache
   - Deleted on exchange

2. Opaque Access Token
   - Given to Claude
   - 60-minute lifetime
   - Maps to JWT internally
   - 256-bit random

3. JWT Access Token
   - Used by MCP server
   - Contains user claims
   - Signed with proxy key
   - Validated on each request

4. Entra ID Token
   - Never exposed externally
   - Stored in token mapping
   - Used for user claim extraction
   - Refreshed if available
```

### Data Protection

ASP.NET Core Data Protection configuration:

```csharp
builder.Services.AddDataProtection()
    .SetApplicationName("MCPProxy")
    .PersistKeysToFileSystem(new DirectoryInfo("./keys"))
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .ProtectKeysWithDpapi();  // Windows
    // or .ProtectKeysWithCertificate(cert);  // Cross-platform
```

### Security Checklist

✅ **Cryptographic Security**
- PKCE with SHA-256
- AES-256 state encryption
- RSA-2048 JWT signatures
- Cryptographically secure random tokens

✅ **Protocol Security**
- CSRF protection (state parameter)
- Redirect URI validation
- Token binding (code_verifier)
- Audience validation (aud claim)

✅ **Operational Security**
- HTTPS enforcement
- CORS restrictions
- Short token lifetimes
- Structured logging (no secrets)

---

## Performance Considerations

### Caching Strategy

```
In-memory (ConcurrentDictionary):
    - PKCE State: 10 min TTL
    - Login Tokens: 5 min TTL

Configurable Storage (InMemory or AzureTableStorage):
    - Authorization Codes: 5 min TTL
    - Access Tokens: 60 min TTL
    - Client Registrations: No TTL (persistent)
```

### Scaling Options

**Single Instance (current default)**:
- `ConcurrentDictionary` for PKCE state and login tokens (in-process)
- Configurable stores for tokens and clients (InMemory or AzureTableStorage)
- Fast (sub-millisecond for in-memory)
- No external dependencies (InMemory mode)

**Multi-Instance (production)**:
- **Azure Table Storage** (included) - For tokens and clients
- **Redis** (future) - Distributed cache for PKCE state and login tokens
- **SQL Server** (future) - Persistent storage with audit trail

---

## Persistent Storage Recommendations

### Current Implementation

The project includes **four storage implementations**:

**1. TokenStore - InMemoryTokenStore (Default - Development)**

Uses a static `ConcurrentDictionary<string, TokenData>` for all token data.

See full implementation: `MCP/Services/TokenStore/InMemoryTokenStore.cs`

**2. TokenStore - AzureTableTokenStore (Production)**

Uses Azure Table Storage for persistent, scalable token storage. See implementation details in previous section.

**3. ClientStore - InMemoryClientStore (Default - Development)**

Uses a static `ConcurrentDictionary<string, ClientMapping>` with **deterministic client IDs**.

Key implementation details:
- Uses SHA-256 hash of (clientName + redirectUris + scopes) for deterministic client ID
- Same parameters = same client ID (idempotent)

See full implementation: `MCP/Services/ClientStore/InMemoryClientStore.cs`

**Why deterministic client IDs?**
- ✅ Idempotent registration (same params = same ID)
- ✅ Works well with Claude AI (auto-registers on each restart)
- ❌ **Does NOT work with ChatGPT** (registers once, expects persistent ID)

**4. ClientStore - AzureTableClientStore (Production)**

Uses Azure Table Storage with **random GUIDs** for client IDs.

Key implementation details:
- Uses `Guid.NewGuid().ToString("N")` for client IDs (32 hex characters)
- PartitionKey: "ClientRegistration" (single partition)
- RowKey: proxyClientId

See full implementation: `MCP/Services/ClientStore/AzureTableClientStore.cs`

**Why random GUIDs in Azure Table?**
- ✅ Persistent across application restarts
- ✅ **Required for ChatGPT** compatibility
- ✅ Simpler implementation (no hashing needed)
- ✅ Better distribution in Azure Table Storage

**Configuration in appsettings.json**:
```json
{
  "TokenStore": {
    "Provider": "AzureTableStorage",
    "AzureTableStorage": {
      "ConnectionString": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net",
      "TableName": "TokenMappings"
    }
  },
  "ClientStore": {
    "Provider": "AzureTableStorage",
    "AzureTableStorage": {
      "ConnectionString": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net",
      "TableName": "ClientRegistrations"
    }
  }
}
```

**Features**:
- ✅ **Persistent storage** - Survives application restarts
- ✅ **Scalable** - Works with multiple server instances
- ✅ **Automatic cleanup** - Expired tokens (>90 days) removed on startup
- ✅ **Encrypted at rest** - Azure Storage Service Encryption (256-bit AES)
- ✅ **Cost-effective** - Pay only for what you use (~$0.045 per GB/month)
- ✅ **No additional keys** - Uses Azure's built-in encryption

### Production Storage Comparison

| Storage | Speed | Scalability | Persistence | Cost | Complexity | Recommended For |
|---------|-------|-------------|-------------|------|------------|-----------------|
| **Redis** | ⚡⚡⚡⚡⚡ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 💰💰 | ⚙️⚙️ | **Production web farms** |
| **SQL Server** | ⚡⚡⚡ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 💰💰💰 | ⚙️⚙️⚙️ | **Enterprise with compliance** |
| **Azure Table Storage** | ⚡⚡⚡⚡ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 💰 | ⚙️⚙️ | **Cost-sensitive cloud deployments** |
| **Cosmos DB** | ⚡⚡⚡⚡ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 💰💰💰💰 | ⚙️⚙️⚙️ | **Global distribution required** |

### Recommended: Redis for Production

**Why Redis is recommended**:

1. **Fast** - Sub-millisecond latency (similar to in-memory)
2. **Distributed** - Works with multiple server instances
3. **TTL Support** - Automatic expiration (like IMemoryCache)
4. **Simple Migration** - Interface stays the same
5. **Battle-tested** - Used by major platforms (GitHub, Stack Overflow, etc.)

**Implementation**: See [README-Customization.md - Redis Implementation](../README-Customization.md#redis-implementation)

**Azure Redis Cache**:
```bash
# Create Azure Redis Cache
az redis create \
  --name mcp-oauth-cache \
  --resource-group mcp-resources \
  --location westeurope \
  --sku Basic \
  --vm-size c0
```

**Connection string**:
```json
{
  "ConnectionStrings": {
    "Redis": "mcp-oauth-cache.redis.cache.windows.net:6380,password=YOUR_KEY,ssl=True,abortConnect=False"
  }
}
```

### Alternative: SQL Server for Audit Requirements

If you need:
- **Audit trail** of all token operations
- **Compliance** (GDPR, HIPAA, etc.)
- **Complex queries** (user reports, analytics)
- **Long-term data retention**

**Implementation**: See [README-Customization.md - SQL Server Implementation](../README-Customization.md#sql-server-implementation)

**Database schema**:
```sql
CREATE TABLE TokenMappings (
    OpaqueToken NVARCHAR(255) PRIMARY KEY,
    ProxyJwtToken NVARCHAR(MAX) NOT NULL,
    EntraAccessToken NVARCHAR(MAX) NOT NULL,
    Subject NVARCHAR(255) NOT NULL,
    Resource NVARCHAR(500) NOT NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    ExpiresAt DATETIME2 NOT NULL,
    RevokedAt DATETIME2 NULL,
    INDEX IX_Subject (Subject),
    INDEX IX_ExpiresAt (ExpiresAt)
);

-- Audit table
CREATE TABLE TokenAuditLog (
    Id BIGINT IDENTITY PRIMARY KEY,
    OpaqueToken NVARCHAR(255) NOT NULL,
    Operation NVARCHAR(50) NOT NULL, -- CREATE, RETRIEVE, REVOKE
    IpAddress NVARCHAR(45),
    UserAgent NVARCHAR(500),
    Timestamp DATETIME2 NOT NULL DEFAULT GETUTCDATE()
);
```

### Migration Path

**Step 1**: Extract interface (already done):
```csharp
public interface ITokenStore
{
    Task StoreCodeData(TokenData codeData);
    Task<TokenData?> GetAndConsumeCode(string code);
}
```

**Step 2**: Choose your storage provider

For most deployments, **Azure Table Storage is included and ready to use**:

```json
// In appsettings.json
{
  "TokenStore": {
    "Provider": "AzureTableStorage",
    "AzureTableStorage": {
      "ConnectionString": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;",
      "TableName": "TokenMappings"
    }
  }
}
```

The implementation handles:
- ✅ Automatic table creation
- ✅ Token expiration (90 days)
- ✅ Cleanup on startup
- ✅ Encryption at rest (Azure SSE)

**Step 3**: For Redis/SQL alternatives (not included):

```csharp
// In Program.cs - Azure Table (included for both stores):

// TokenStore
if (tokenStoreProvider == "AzureTableStorage")
{
    var connectionString = builder.Configuration["TokenStore:AzureTableStorage:ConnectionString"]!;
    var tableName = builder.Configuration["TokenStore:AzureTableStorage:TableName"] ?? "TokenMappings";
    builder.Services.AddSingleton<ITokenStore>(new AzureTableTokenStore(connectionString, tableName));
}
else // InMemory (default)
{
    builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>();
}

// ClientStore
if (clientStoreProvider == "AzureTableStorage")
{
    var connectionString = builder.Configuration["ClientStore:AzureTableStorage:ConnectionString"]!;
    var tableName = builder.Configuration["ClientStore:AzureTableStorage:TableName"] ?? "ClientRegistrations";
    builder.Services.AddSingleton<IClientStore>(new AzureTableClientStore(connectionString, tableName));
}
else // InMemory (default)
{
    builder.Services.AddSingleton<IClientStore, InMemoryClientStore>();
}

// For Redis/SQL (requires custom implementation):
// builder.Services.AddSingleton<ITokenStore, RedisTokenStore>();
// builder.Services.AddSingleton<ITokenStore, SqlTokenStore>();
// builder.Services.AddSingleton<IClientStore, RedisClientStore>();
// builder.Services.AddSingleton<IClientStore, SqlClientStore>();
```

**Step 4**: Deploy and test
- Verify tokens persist across restarts
- Test with multiple instances
- Monitor performance metrics

---

## References

- **[Model Context Protocol C# SDK](https://github.com/modelcontextprotocol/csharp-sdk)** - Official .NET implementation (game-changer for this project)
- **RFC 6749** - OAuth 2.0 Authorization Framework
- **RFC 7591** - OAuth 2.0 Dynamic Client Registration Protocol
- **RFC 7636** - Proof Key for Code Exchange (PKCE)
- **RFC 8414** - OAuth 2.0 Authorization Server Metadata
- **RFC 8707** - Resource Indicators for OAuth 2.0
- **RFC 9728** - OAuth 2.0 Protected Resource Metadata
- **MCP Specification** - Version 2025-06-18
- **Microsoft Entra ID** - OAuth 2.0 and OpenID Connect documentation

---

**For implementation details, see the source code in `Controllers/`, `Services/`, and `Models/` directories.**

**For persistent storage implementations, see [README-Customization.md](../README-Customization.md).**
