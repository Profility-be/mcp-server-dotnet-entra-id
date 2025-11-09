namespace MCP.Models;

/// <summary>
/// Stores dynamic client registration data (RFC 7591).
/// Maps Claude's registered client to its configuration.
/// </summary>
public class ClientMapping
{
    /// <summary>
    /// The proxy client ID generated for Claude (deterministic hash)
    /// </summary>
    public required string ProxyClientId { get; set; }

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
