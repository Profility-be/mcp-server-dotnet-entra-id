namespace MCP.Models;

/// <summary>
/// Represents a temporary login token for the custom login page flow.
/// Used to maintain state between the authorization request and the login page.
/// </summary>
public class LoginTokenData
{
    /// <summary>
    /// The unique login token (random GUID)
    /// </summary>
    public required string Token { get; set; }

    /// <summary>
    /// The encrypted state parameter containing PKCE data
    /// </summary>
    public required string EncryptedState { get; set; }

    /// <summary>
    /// When this login token was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When this login token expires (default: 10 minutes)
    /// </summary>
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddMinutes(10);

    /// <summary>
    /// Whether this token has been used (prevents replay attacks)
    /// </summary>
    public bool IsUsed { get; set; } = false;
}
