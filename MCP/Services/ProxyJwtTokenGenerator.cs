using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MCP.Controllers; // For UserClaims

namespace MCP.Services;

/// <summary>
/// Generates proxy JWT tokens for Claude that can be validated by the MCP server.
/// These tokens contain the correct 'aud' claim (MCP server URL) per RFC 8707.
/// </summary>
public interface IProxyJwtTokenGenerator
{
    string GenerateAccessToken(string clientId, string userIdentifier, string mcpServerUrl, string scopes, UserClaims? userClaims = null);
    string GenerateOpaqueToken();
    bool ValidateCodeVerifier(string codeVerifier, string codeChallenge);
    string GenerateCodeVerifier();
    string GenerateCodeChallenge(string codeVerifier);
}

public class ProxyJwtTokenGenerator : IProxyJwtTokenGenerator
{
    private readonly IAppConfiguration _configuration;
    private readonly ILogger<ProxyJwtTokenGenerator> _logger;
    private readonly SymmetricSecurityKey _signingKey;

    public ProxyJwtTokenGenerator(IAppConfiguration configuration, ILogger<ProxyJwtTokenGenerator> logger)
    {
        _configuration = configuration;
        _logger = logger;
        
        // Generate or retrieve signing key
        // In production, store this in Azure Key Vault
        var keyString = _configuration["Jwt:SigningKey"] ?? GenerateRandomKey();
        var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(keyString));
        _signingKey = new SymmetricSecurityKey(keyBytes);
    }

    public string GenerateAccessToken(string clientId, string userIdentifier, string mcpServerUrl, string scopes, UserClaims? userClaims = null)
    {
        _logger.LogInformation("Generating JWT access token for client: {ClientId}", clientId);
        
        var expirationMinutes = _configuration.JwtExpirationMinutes; 
        
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userIdentifier),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("client_id", clientId),
            new("scope", scopes)
        };

        // Add user claims from Entra ID token if available
        if (userClaims == null)
        {
            _logger.LogWarning("No user claims available for JWT");
        }
        
        if (userClaims != null)
        {
            if (!string.IsNullOrEmpty(userClaims.Name))
                claims.Add(new Claim(JwtRegisteredClaimNames.Name, userClaims.Name));
            
            if (!string.IsNullOrEmpty(userClaims.Email))
                claims.Add(new Claim(JwtRegisteredClaimNames.Email, userClaims.Email));
            
            if (!string.IsNullOrEmpty(userClaims.GivenName))
                claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, userClaims.GivenName));
            
            if (!string.IsNullOrEmpty(userClaims.FamilyName))
                claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, userClaims.FamilyName));
            
            if (!string.IsNullOrEmpty(userClaims.ObjectId))
                claims.Add(new Claim("oid", userClaims.ObjectId));
            
            if (!string.IsNullOrEmpty(userClaims.PreferredUsername))
                claims.Add(new Claim("preferred_username", userClaims.PreferredUsername));
            
            if (!string.IsNullOrEmpty(userClaims.Upn))
                claims.Add(new Claim("upn", userClaims.Upn));
            
            if (!string.IsNullOrEmpty(userClaims.TenantId))
                claims.Add(new Claim("tid", userClaims.TenantId));
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
