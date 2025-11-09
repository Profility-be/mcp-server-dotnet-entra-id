namespace MCP.Models;

/// <summary>
/// Unified model for single-use codes in both authorization_code and refresh_token flows.
/// Each code is consumed once (removed from store), then a new code is generated.
/// </summary>
public class TokenData
{
    /// <summary>
    /// The single-use code (used for both initial auth and refresh)
    /// </summary>
    public required string Code { get; set; }

    /// <summary>
    /// The real Entra ID refresh token
    /// </summary>
    public required string EntraRefreshToken { get; set; }

    /// <summary>
    /// User claims (extracted from ID token)
    /// </summary>
    public MCP.Controllers.UserClaims? UserClaims { get; set; }

    /// <summary>
    /// PKCE state data (client ID, scopes, etc.)
    /// </summary>
    public required PkceStateData PkceState { get; set; }

    /// <summary>
    /// When this code was created
    /// </summary>
    public DateTime CreatedAt { get; set; }
}
