using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.Server;
using System.Text;
using System.Security.Cryptography;
using MCP.Services;

var builder = WebApplication.CreateBuilder(args);

// Add Memory Cache for in-memory storage
builder.Services.AddMemoryCache();

// Add HttpClient factory for Entra ID token exchange
builder.Services.AddHttpClient();

// Add HttpContextAccessor for accessing user claims in MCP tools
builder.Services.AddHttpContextAccessor();

// Register OAuth proxy services
builder.Services.AddSingleton<IPkceStateManager, PkceStateManager>();
builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>();
builder.Services.AddSingleton<ILoginTokenStore, InMemoryLoginTokenStore>();
builder.Services.AddSingleton<IClientStore, InMemoryClientStore>();
builder.Services.AddSingleton<IProxyJwtTokenGenerator, ProxyJwtTokenGenerator>();
builder.Services.AddSingleton<IBrandingProvider, BrandingProvider>();

// Add Controllers for OAuth endpoints
builder.Services.AddControllers();

// Add Razor Pages for login view
builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();

// Configure JWT Bearer authentication for MCP endpoints
var jwtSigningKey = builder.Configuration["Jwt:SigningKey"] ?? GenerateRandomKey();
var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(jwtSigningKey));
var signingKey = new SymmetricSecurityKey(keyBytes);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["MCP:ServerUrl"],
            ValidAudience = builder.Configuration["MCP:ServerUrl"],
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.FromMinutes(5)
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
            .AllowCredentials();
    });
});

// MCP Server configureren voor HTTP transport
builder.Services.AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly();

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
// Note: MCP uses /sse for SSE transport, not /
app.MapMcp().RequireAuthorization();

app.Logger.LogInformation("Profility MCP OAuth Proxy starting...");
app.Logger.LogInformation("MCP Server URL: {ServerUrl}", builder.Configuration["MCP:ServerUrl"]);
app.Logger.LogInformation("Azure AD Tenant: {TenantId}", builder.Configuration["AzureAd:TenantId"]);
app.Logger.LogInformation("Azure AD Client: {ClientId}", builder.Configuration["AzureAd:ClientId"]);

app.Run();

// Helper function to generate random key
static string GenerateRandomKey()
{
    var bytes = new byte[64];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(bytes);
    return Convert.ToBase64String(bytes);
}
