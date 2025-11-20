using MCP.Models;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Profility.MCP.Services.ClientStore;

/// <summary>
/// In-memory implementation of IClientStore.
/// Uses deterministic client IDs based on registration parameters.
/// Same parameters = same client ID (persistent across restarts with same params).
/// </summary>
public class InMemoryClientStore : IClientStore
{
    private static readonly ConcurrentDictionary<string, ClientMapping> _clients = new();

    public Task<string> RegisterClient(string clientName, List<string> redirectUris, string? requestedScopes)
    {
        // Generate deterministic client ID based on registration parameters
        var proxyClientId = GenerateDeterministicClientId(clientName, redirectUris, requestedScopes);

        // Store or update mapping (idempotent)
        var mapping = new ClientMapping
        {
            ProxyClientId = proxyClientId,
            RedirectUris = redirectUris,
            RequestedScopes = requestedScopes,
            ClientName = clientName,
            CreatedAt = DateTime.UtcNow
        };

        _clients[proxyClientId] = mapping;
        return Task.FromResult(proxyClientId);
    }

    public Task<ClientMapping?> GetClientMapping(string proxyClientId)
    {
        _clients.TryGetValue(proxyClientId, out var mapping);
        return Task.FromResult(mapping);
    }

    private static string GenerateDeterministicClientId(string clientName, List<string> redirectUris, string? scopes)
    {
        // Create stable hash input (sorted for consistency)
        var sortedRedirects = string.Join("|", redirectUris.OrderBy(x => x));
        var input = $"{clientName}|{sortedRedirects}|{scopes ?? ""}";
        
        // Generate SHA-256 hash
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        
        // Convert to base64url (RFC 7515) and take first 32 chars for readability
        var base64 = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
        
        return base64[..32]; // 32 characters = 192 bits of entropy
    }
}
