using MCP.Models;

namespace Profility.MCP.Services.ClientStore;

/// <summary>
/// Interface for client registration storage implementations.
/// Manages dynamic client registration for Claude (RFC 7591).
/// </summary>
public interface IClientStore
{
    /// <summary>
    /// Register a new client and return a client ID.
    /// Implementation can use deterministic or random client IDs.
    /// </summary>
    Task<string> RegisterClient(string clientName, List<string> redirectUris, string? requestedScopes);
    
    /// <summary>
    /// Get client mapping by proxy client ID.
    /// Returns null if client is not found.
    /// </summary>
    Task<ClientMapping?> GetClientMapping(string proxyClientId);
}
