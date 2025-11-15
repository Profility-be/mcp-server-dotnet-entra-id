using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MCP.Controllers; // For UserClaims

namespace MCP.Services.Jwt;

/// <summary>
/// Generates proxy JWT tokens for Claude that can be validated by the MCP server.
/// These tokens contain the correct 'aud' claim (MCP server URL) per RFC 8707.
/// </summary>
public interface IJwtBuilder
{
    /// <summary>
    /// Builds a JWT access token for the authenticated user.
    /// This token is used by Claude to access MCP tools and contains user claims from Entra ID.
    /// The token has the MCP server URL as audience (aud claim) per RFC 8707 Resource Indicators.
    /// Used in the OAuth token exchange flow after successful Entra ID authentication.
    /// </summary>
    string BuildJwt(string clientId, string userIdentifier, string scopes, UserClaims? userClaims = null);

    /// <summary>
    /// Generates a cryptographically secure opaque token for external use.
    /// These tokens are given to Claude and map internally to JWT tokens with user claims.
    /// Used to maintain separation between external tokens (opaque) and internal tokens (JWT).
    /// </summary>
    string GenerateOpaqueToken();

    /// <summary>
    /// Validates a PKCE code verifier against its corresponding code challenge.
    /// Ensures the code_verifier sent by Claude matches the code_challenge from the authorization request.
    /// Critical for PKCE security in the OAuth authorization code flow.
    /// </summary>
    bool ValidateCodeVerifier(string codeVerifier, string codeChallenge);

    /// <summary>
    /// Generates a cryptographically secure PKCE code verifier.
    /// Used by the proxy when acting as OAuth client to Entra ID in the dual PKCE flow.
    /// The code verifier is 43-128 characters of unreserved characters per RFC 7636.
    /// </summary>
    string GenerateCodeVerifier();

    /// <summary>
    /// Generates a PKCE code challenge from a code verifier.
    /// Computed as BASE64URL(SHA256(ASCII(code_verifier))) per RFC 7636.
    /// Used in the authorization request to Entra ID to prevent authorization code interception attacks.
    /// </summary>
    string GenerateCodeChallenge(string codeVerifier);
}

public class JwtBuilder : IJwtBuilder
{
    private readonly IAppConfiguration _configuration;
    private readonly ILogger<JwtBuilder> _logger;
    private readonly SymmetricSecurityKey _signingKey;
    private readonly IEnumerable<IClaimProvider> _claimProviders;

    public JwtBuilder(IAppConfiguration configuration, ILogger<JwtBuilder> logger, IEnumerable<IClaimProvider> claimProviders)
    {
        _configuration = configuration;
        _logger = logger;
        _claimProviders = claimProviders;
        
        // Generate or retrieve signing key
        // In production, store this in Azure Key Vault
        var keyString = _configuration["Jwt:SigningKey"] ?? GenerateRandomKey();
        var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(keyString));
        _signingKey = new SymmetricSecurityKey(keyBytes);
    }

    public string BuildJwt(string clientId, string userIdentifier, string scopes, UserClaims? userClaims = null)
    {
        _logger.LogInformation("Generating JWT access token for client: {ClientId}", clientId); 
        
        string mcpServerUrl = _configuration["MCP:ServerUrl"]!;
        var expirationMinutes = _configuration.JwtExpirationMinutes; 
        
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userIdentifier), // Subject: unique identifier for the user
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID: unique identifier for this token
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), // Issued At: timestamp when token was issued
            new("client_id", clientId),
            new("scope", scopes)
        };

        // New step: Call all claim providers to add extra claims
        var context = new ClaimProviderContext
        {
            ClientId = clientId,
            UserIdentifier = userIdentifier,
            McpServerUrl = mcpServerUrl,
            Scopes = scopes,
            EntraIDUserClaims = userClaims
        };

        foreach (var provider in _claimProviders)
        {
            try
            {
                provider.AddClaims(claims, context);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Claim provider {ProviderType} failed to add claims", provider.GetType().Name);
                // Continue with next providers (fail-safe)
            }
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(expirationMinutes),
            Issuer = mcpServerUrl, // The proxy acts as issuer
            Audience = mcpServerUrl, // Critical: aud must be MCP server URL (RFC 8707)
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256Signature)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtString = tokenHandler.WriteToken(token);
        
        _logger.LogInformation("JWT generated successfully with {ClaimCount} claims", claims.Count);
        
        return jwtString;
    }

    public string GenerateOpaqueToken()
    {
        // Generate a cryptographically secure random opaque token
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }

    public bool ValidateCodeVerifier(string codeVerifier, string codeChallenge)
    {
        // Compute SHA-256 hash of the code verifier
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        
        // Base64url encode the hash
        var computedChallenge = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");

        // Compare with the provided code challenge
        return computedChallenge == codeChallenge;
    }

    public string GenerateCodeVerifier()
    {
        // RFC 7636: 43-128 characters, unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        // Generate 32 random bytes which will result in 43 base64url characters
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }

    public string GenerateCodeChallenge(string codeVerifier)
    {
        // RFC 7636: BASE64URL(SHA256(ASCII(code_verifier)))
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        
        return Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }

    private static string GenerateRandomKey()
    {
        var bytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}
