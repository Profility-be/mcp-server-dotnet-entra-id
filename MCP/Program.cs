using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.AspNetCore.Authentication;
using System.Text;
using System.Security.Cryptography;
using MCP.Services;
using MCP.Services.Jwt;
using Profility.MCP.Services.TokenStore;
using Profility.MCP.Services.ClientStore;

var builder = WebApplication.CreateBuilder(args);

// Register IAppConfiguration as a singleton wrapper around IConfiguration
// Also register as IConfiguration so both interfaces resolve to the same instance
var appConfiguration = new AppConfiguration(builder.Configuration);
builder.Services.AddSingleton<IAppConfiguration>(appConfiguration);
builder.Services.AddSingleton<IConfiguration>(appConfiguration);

// Add Memory Cache for in-memory storage
builder.Services.AddMemoryCache();

// Add HttpClient factory for Entra ID token exchange
builder.Services.AddHttpClient();

// Add HttpContextAccessor for accessing user claims in MCP tools
// NOTE: MCP tools should prefer RequestContext<T>.User over IHttpContextAccessor (see WhoAmITool).
// This registration stays for the OAuth controllers and for custom tools that still depend on it.
builder.Services.AddHttpContextAccessor();

// Register OAuth proxy services
builder.Services.AddSingleton<IPkceStateManager, PkceStateManager>();

// Configure TokenStore based on appsettings
var tokenStoreProvider = builder.Configuration["TokenStore:Provider"] ?? "InMemory";
if (tokenStoreProvider.Equals("AzureTableStorage", StringComparison.OrdinalIgnoreCase))
{
    var connectionString = builder.Configuration["TokenStore:AzureTableStorage:ConnectionString"]
        ?? throw new InvalidOperationException("TokenStore:AzureTableStorage:ConnectionString is required when using AzureTableStorage provider");
    var tableName = builder.Configuration["TokenStore:AzureTableStorage:TableName"] ?? "TokenMappings";

    builder.Services.AddSingleton<ITokenStore>(sp => new AzureTableTokenStore(connectionString, tableName));
}
else // InMemory (default)
{
    builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>();
}

// Configure ClientStore based on appsettings
var clientStoreProvider = builder.Configuration["ClientStore:Provider"] ?? "InMemory";
if (clientStoreProvider.Equals("AzureTableStorage", StringComparison.OrdinalIgnoreCase))
{
    var connectionString = builder.Configuration["ClientStore:AzureTableStorage:ConnectionString"]
        ?? throw new InvalidOperationException("ClientStore:AzureTableStorage:ConnectionString is required when using AzureTableStorage provider");
    var tableName = builder.Configuration["ClientStore:AzureTableStorage:TableName"] ?? "ClientRegistrations";
    
    builder.Services.AddSingleton<Profility.MCP.Services.ClientStore.IClientStore>(sp => new AzureTableClientStore(connectionString, tableName));
}
else // InMemory (default)
{
    builder.Services.AddSingleton<Profility.MCP.Services.ClientStore.IClientStore, Profility.MCP.Services.ClientStore.InMemoryClientStore>();
}

builder.Services.AddSingleton<ILoginTokenStore, InMemoryLoginTokenStore>();
builder.Services.AddSingleton<IJwtBuilder, JwtBuilder>();
builder.Services.AddSingleton<IBrandingProvider, BrandingProvider>();

// Register claim providers
builder.Services.AddSingleton<IClaimProvider, DefaultClaimProvider>();  // Default provider (adds standard Entra ID claims)
builder.Services.AddSingleton<IClaimProvider, SampleClaimProvider>();   // Sample custom claim provider
// Other claim providers can be registered here

// Add Controllers for OAuth endpoints
builder.Services.AddControllers();

// Add Razor Pages for login view
builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();

// The MCP server URL doubles as the OAuth issuer, the token audience (RFC 8707) and the
// protected-resource identifier (RFC 9728). AppConfiguration strips any trailing slash so all
// three stay byte-identical: an MCP client rejects an issuer that does not match exactly.
var mcpServerUrl = appConfiguration["MCP:ServerUrl"]!;
var entraClientId = appConfiguration["AzureAd:ClientId"];

// Configure JWT Bearer authentication for MCP endpoints
var jwtSigningKey = builder.Configuration["Jwt:SigningKey"] ?? GenerateRandomKey();
var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(jwtSigningKey));
var signingKey = new SymmetricSecurityKey(keyBytes);

builder.Services.AddAuthentication(options =>
    {
        // JWT Bearer validates the proxy-issued access token...
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        // ...while the MCP scheme owns the 401 challenge, so the response carries a
        // WWW-Authenticate header with a resource_metadata parameter (RFC 9728). That header is
        // how an MCP client discovers which authorization server to use, without hardcoding it.
        options.DefaultChallengeScheme = McpAuthenticationDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = mcpServerUrl,
            ValidAudience = mcpServerUrl,
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    })
    .AddMcp(options =>
    {
        // ResourceMetadataUri is deliberately left at its default. The handler then both serves
        // and advertises /.well-known/oauth-protected-resource relative to the incoming request.
        // Do not pin it to an absolute URL on a different host than the request: the handler
        // matches the request against it, so the document stops being served (404) and only the
        // challenge header still points at it. If a reverse proxy rewrites the Host header,
        // configure forwarded headers instead of overriding this.

        // RFC 9728 Protected Resource Metadata, served by the SDK at
        // /.well-known/oauth-protected-resource. This proxy is its own authorization server,
        // so the metadata points back at itself.
        options.ResourceMetadata = new()
        {
            Resource = mcpServerUrl,
            AuthorizationServers = { mcpServerUrl },
            ScopesSupported =
            [
                $"api://{entraClientId}/MCP.Access",
                "openid",
                "profile",
                "email"
            ],
            BearerMethodsSupported = ["header"],
            ResourceDocumentation = $"{mcpServerUrl}/docs"
        };
    });

builder.Services.AddAuthorization();

// Configure CORS for Claude AI
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
                "https://claude.ai",
                "https://api.claude.ai"
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            // A browser-based MCP client can only read the challenge - and therefore discover the
            // authorization server - if WWW-Authenticate is exposed to script.
            .WithExposedHeaders(HeaderNames.WWWAuthenticate)
            .AllowCredentials();
    });
});

// How the MCP endpoint tracks state between requests.
//
//   Stateless (default)          - no Mcp-Session-Id and no session affinity, so the app scales
//                                  out freely. The GET/DELETE and /sse endpoints are unavailable,
//                                  and so are server-to-client requests: sampling, elicitation
//                                  and roots. Use MRTR if a tool needs to ask the user something.
//   StatefulForInitializeClients - hybrid: clients on protocol revision 2026-07-28 or later are
//                                  served statelessly, while older initialize-handshake clients
//                                  still get a real session on the same endpoint. Needs affinity.
//   Stateful                     - a long-lived session for every client, closest to the
//                                  pre-2.0 behaviour. Modern clients are forced to downgrade.
//
// Stateless is the SDK 2.x default and the right choice for a new server. Override MCP:SessionMode
// only if you have clients that depend on the old behaviour - see UPGRADING.md.
var sessionMode = Enum.TryParse<HttpServerSessionMode>(
        appConfiguration["MCP:SessionMode"], ignoreCase: true, out var configuredSessionMode)
    ? configuredSessionMode
    : HttpServerSessionMode.Stateless;

// Legacy HTTP+SSE transport (/sse and /message, protocol revision 2024-11-05). Off by default:
// it has no HTTP-level backpressure and Streamable HTTP supersedes it. Needs a stateful mode.
var enableLegacySse = appConfiguration.GetValue("MCP:EnableLegacySse", false);

builder.Services.AddMcpServer()
    .WithHttpTransport(options =>
    {
        options.SessionMode = sessionMode;

        if (enableLegacySse)
        {
            // MCP9004: the SDK marks legacy SSE obsolete on purpose. It is opt-in here purely so
            // existing deployments can keep older clients working while they migrate.
#pragma warning disable MCP9004
            options.EnableLegacySse = true;
#pragma warning restore MCP9004
        }
    })
    .WithToolsFromAssembly()
    // Audit trail for every tool call. Registered before the authorization filters on purpose, so
    // this wraps them and a call that is rejected still leaves a record.
    .WithRequestFilters(filters => filters.AddCallToolFilter(ToolAuditLog.Filter))
    // Honours [Authorize] and [AllowAnonymous] on tools, prompts and resources, and filters
    // tools/list per user. The SDK docs recommend always calling this with ASP.NET Core.
    .AddAuthorizationFilters();

// Add logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles(); // Enable static files for CSS

app.UseRouting();

app.UseCors(); // Enable CORS

app.UseAuthentication(); // Enable JWT authentication
app.UseAuthorization();

// Health check endpoint for Azure warmup
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow })).AllowAnonymous();

// Map controllers (for OAuth endpoints and WellKnown)
app.MapControllers();

// Map MCP endpoints with JWT authentication
// CRITICAL: MCP tools are protected by JWT Bearer tokens
// Claude must send: Authorization: Bearer {jwt_token}
// This maps the Streamable HTTP transport at the application root. The legacy /sse and /message
// endpoints are only mapped when MCP:EnableLegacySse is enabled.
app.MapMcp().RequireAuthorization();

app.Logger.LogInformation("Profility MCP OAuth Proxy starting...");
app.Logger.LogInformation("MCP Server URL: {ServerUrl}", mcpServerUrl);
app.Logger.LogInformation("MCP session mode: {SessionMode} (legacy SSE: {LegacySse})", sessionMode, enableLegacySse);
app.Logger.LogInformation("Azure AD Tenant: {TenantId}", appConfiguration["AzureAd:TenantId"]);
app.Logger.LogInformation("Azure AD Client: {ClientId}", entraClientId);

app.Run();

// Helper function to generate random key
static string GenerateRandomKey()
{
    var bytes = new byte[64];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(bytes);
    return Convert.ToBase64String(bytes);
}
