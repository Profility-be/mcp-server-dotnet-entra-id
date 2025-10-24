namespace MCP.Models;

/// <summary>
/// Maps proxy tokens (opaque tokens given to Claude) to real Entra ID tokens.
/// This implements the Phantom Token Pattern for security.
/// </summary>
public class TokenMapping
{
    /// <summary>
    /// The opaque access token given to Claude
    /// </summary>
    public required string ProxyAccessToken { get; set; }

    /// <summary>
    /// The real Entra ID access token (JWT)
    /// </summary>
    public required string EntraAccessToken { get; set; }

    /// <summary>
    /// The opaque refresh token given to Claude (optional)
    /// </summary>
    public string? ProxyRefreshToken { get; set; }

    /// <summary>
    /// The real Entra ID refresh token (optional)
    /// </summary>
    public string? EntraRefreshToken { get; set; }

    /// <summary>
    /// The client ID that owns this token
    /// </summary>
    public required string ClientId { get; set; }

    /// <summary>
    /// The authorization code that was exchanged for these tokens
    /// </summary>
    public required string AuthorizationCode { get; set; }

    /// <summary>
    /// The user's email or unique identifier from Entra ID
    /// </summary>
    public string? UserIdentifier { get; set; }

    /// <summary>
    /// Full user claims from Entra ID token (name, email, oid, etc.)
    /// </summary>
    public MCP.Controllers.UserClaims? UserClaims { get; set; }

    /// <summary>
    /// When the access token expires
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// When this mapping was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The scopes granted to this token
    /// </summary>
    public string? Scopes { get; set; }
}
