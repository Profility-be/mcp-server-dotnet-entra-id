namespace MCP.Models;

/// <summary>
/// Maps a dynamic client ID (generated for Claude) to the real Entra ID app registration.
/// This enables fake Dynamic Client Registration (RFC 7591).
/// </summary>
public class ClientMapping
{
    /// <summary>
    /// The proxy client ID generated for Claude
    /// </summary>
    public required string ProxyClientId { get; set; }

    /// <summary>
    /// The real Entra ID application (client) ID
    /// </summary>
    public required string EntraClientId { get; set; }

    /// <summary>
    /// The Entra ID tenant ID
    /// </summary>
    public required string EntaTenantId { get; set; }

    /// <summary>
    /// The redirect URIs requested by Claude
    /// </summary>
    public List<string> RedirectUris { get; set; } = new();

    /// <summary>
    /// The scopes requested by Claude
    /// </summary>
    public string? RequestedScopes { get; set; }

    /// <summary>
    /// When this client was registered
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Client name (usually "claudeai")
    /// </summary>
    public string? ClientName { get; set; }
}
