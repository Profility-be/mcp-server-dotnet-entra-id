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

- `IMemoryCache` for PKCE state
- `IMemoryCache` for token mappings
- `IMemoryCache` for client registrations
- `IMemoryCache` for login tokens

**This is NOT suitable for production** because:
- ❌ Data is lost on application restart
- ❌ Does not work with multiple instances (web farms)
- ❌ No persistence or audit trail
- ❌ Limited scalability

**For production, replace with**:
- ✅ **Redis** (recommended) - Distributed cache, fast, scales horizontally
- ✅ **SQL Server** - Persistent, supports transactions, audit trail
- ✅ **Azure Table Storage** - Cost-effective, serverless, global distribution

See [Persistent Token Storage](#persistent-token-storage-recommendations) below for details.

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

The proxy uses ASP.NET Core Data Protection to encrypt state containing PKCE parameters:

```csharp
public class PkceStateManager
{
    private readonly IDataProtector _protector;
    
    public PkceStateManager(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("OAuth.PKCE.State");
    }
    
    public string CreateState(PkceStateData data)
    {
        var json = JsonSerializer.Serialize(data);
        var encrypted = _protector.Protect(json);
        
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(encrypted))
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
    
    public PkceStateData? ReadState(string state)
    {
        try
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
                          │  (IMemoryCache)   │
                          │                   │
                          │  Mapping:         │
                          │  opaque → JWT     │
                          │  opaque → Entra   │
                          └───────────────────┘
```

### Token Mapping Model

```csharp
public class TokenMapping
{
    public string OpaqueToken { get; set; } = default!;
    public string ProxyJwtToken { get; set; } = default!;
    public string EntraAccessToken { get; set; } = default!;
    public string? EntraIdToken { get; set; }
    public string? EntraRefreshToken { get; set; }
    public string Subject { get; set; } = default!;
    public string Resource { get; set; } = default!;
    public string[] Scopes { get; set; } = Array.Empty<string>();
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    
    // User claims from ID token
    public string? Name { get; set; }
    public string? Email { get; set; }
    public string? PreferredUsername { get; set; }
    public string? ObjectId { get; set; }
}
```

### Token Store Interface

```csharp
public interface ITokenStore
{
    Task<string> StoreTokenAsync(TokenMapping mapping);
    Task<TokenMapping?> GetMappingAsync(string opaqueToken);
    Task<bool> RevokeTokenAsync(string opaqueToken);
    Task CleanupExpiredTokensAsync();
}
```

### In-Memory Implementation

```csharp
public class InMemoryTokenStore : ITokenStore
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<InMemoryTokenStore> _logger;
    
    public async Task<string> StoreTokenAsync(TokenMapping mapping)
    {
        mapping.OpaqueToken = GenerateOpaqueToken();
        
        var expiry = mapping.ExpiresAt - DateTime.UtcNow;
        _cache.Set(
            $"token:{mapping.OpaqueToken}", 
            mapping, 
            expiry);
        
        _logger.LogInformation(
            "Stored token mapping for subject {Subject}, expires at {ExpiresAt}",
            mapping.Subject, mapping.ExpiresAt);
        
        return mapping.OpaqueToken;
    }
    
    public async Task<TokenMapping?> GetMappingAsync(string opaqueToken)
    {
        if (_cache.TryGetValue($"token:{opaqueToken}", out TokenMapping? mapping))
        {
            return mapping;
        }
        
        _logger.LogWarning("Token not found: {Token}", opaqueToken);
        return null;
    }
    
    private static string GenerateOpaqueToken()
    {
        var bytes = new byte[32];  // 256 bits
        RandomNumberGenerator.Fill(bytes);
        
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
```

---

## Custom Login Page Flow

### Why an Intermediate Page?

The custom login page serves multiple purposes:

1. **Branding** - Maintain UX consistency
2. **User Education** - Explain what's happening
3. **Consent** - Show requested permissions
4. **Terms Acceptance** - Legal requirements
5. **Language Localization** - Non-English users

### Flow Sequence

```
┌─────────┐                    ┌──────────────┐                   ┌──────────┐
│ Claude  │                    │ OAuth Proxy  │                   │ Entra ID │
└────┬────┘                    └──────┬───────┘                   └────┬─────┘
     │                                │                                 │
     │ GET /oauth/authorize           │                                 │
     ├───────────────────────────────>│                                 │
     │                                │                                 │
     │ 302 Redirect                   │                                 │
     │ Location: /login?token=xyz     │                                 │
     │<───────────────────────────────┤                                 │
     │                                │                                 │
     │ GET /login?token=xyz           │                                 │
     ├───────────────────────────────>│                                 │
     │                                │                                 │
     │ 200 OK (HTML page)             │                                 │
     │ [Continue] [Cancel]            │                                 │
     │<───────────────────────────────┤                                 │
     │                                │                                 │
     │ POST /login/continue           │                                 │
     ├───────────────────────────────>│                                 │
     │                                │                                 │
     │                                │ 302 Redirect to Entra           │
     │<───────────────────────────────┤────────────────────────────────>│
     │                                │                                 │
     │                                │ [User authenticates]            │
     │                                │                                 │
     │                                │ 302 Redirect with code          │
     │                                │<────────────────────────────────┤
     │                                │                                 │
     │ 302 Redirect to Claude         │                                 │
     │ with authorization code        │                                 │
     │<───────────────────────────────┤                                 │
```

### Login Token Model

```csharp
public class LoginTokenData
{
    public string EncryptedState { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string Resource { get; set; } = default!;
    public string[] Scopes { get; set; } = Array.Empty<string>();
    public DateTime ExpiresAt { get; set; }
}
```

### Security Considerations

**Critical security points:**

1. **Single-use tokens**:
```csharp
public async Task<LoginTokenData?> GetAsync(string token)
{
    if (_cache.TryGetValue($"login:{token}", out LoginTokenData? data))
    {
        _cache.Remove($"login:{token}");  // ← Delete immediately
        return data;
    }
    return null;
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
IMemoryCache:
  - PKCE State: 10 min TTL
  - Login Tokens: 5 min TTL
  - Authorization Codes: 5 min TTL
  - Access Tokens: 60 min TTL
  - Client Registrations: 24 hour TTL
```

### Scaling Options

**Single Instance (current)**:
- IMemoryCache
- Fast (sub-millisecond)
- No external dependencies

**Multi-Instance (future)**:
- Redis (distributed cache)
- SQL Server (persistent)
- Azure Table Storage (cheap)

---

## Persistent Token Storage Recommendations

### Current Implementation (Development Only)

The project currently uses `IMemoryCache` for all stateful data:

```csharp
// Services/InMemoryTokenStore.cs
public class InMemoryTokenStore : ITokenStore
{
    private readonly IMemoryCache _cache;
    
    public async Task<string> StoreTokenAsync(TokenMapping mapping)
    {
        mapping.OpaqueToken = GenerateOpaqueToken();
        
        var expiry = mapping.ExpiresAt - DateTime.UtcNow;
        _cache.Set($"token:{mapping.OpaqueToken}", mapping, expiry);
        
        return mapping.OpaqueToken;
    }
    // ... other methods
}
```

**Why this was chosen for the reference implementation**:
- ✅ Zero external dependencies
- ✅ Simple to understand and debug
- ✅ Fast (sub-millisecond lookups)
- ✅ Good for development and demos

**Why you MUST replace this for production**:
- ❌ **Data loss on restart** - All tokens invalidated when app restarts
- ❌ **Single instance only** - Cannot scale to multiple servers
- ❌ **No audit trail** - Cannot track token usage for security analysis
- ❌ **Memory pressure** - Large token stores consume app memory

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
    Task<string> StoreTokenAsync(TokenMapping mapping);
    Task<TokenMapping?> GetMappingAsync(string opaqueToken);
    Task<bool> RevokeTokenAsync(string opaqueToken);
    Task CleanupExpiredTokensAsync();
}
```

**Step 2**: Implement Redis/SQL version (see Customization guide)

**Step 3**: Swap registration in `Program.cs`:
```csharp
// Before (development):
builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>();

// After (production):
builder.Services.AddSingleton<ITokenStore, RedisTokenStore>();
// OR
builder.Services.AddSingleton<ITokenStore, SqlTokenStore>();
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
