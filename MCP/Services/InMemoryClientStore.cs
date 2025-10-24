using Microsoft.Extensions.Caching.Memory;
using MCP.Models;

namespace MCP.Services;

/// <summary>
/// Manages fake dynamic client registration for Claude.
/// Maps proxy client IDs to the real Entra ID app registration.
/// </summary>
public interface IClientStore
{
    Task<string> RegisterClient(string clientName, List<string> redirectUris, string? requestedScopes);
    Task<ClientMapping?> GetClientMapping(string proxyClientId);
}

public class InMemoryClientStore : IClientStore
{
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;
    private const int CLIENT_EXPIRATION_HOURS = 24;

    public InMemoryClientStore(IMemoryCache cache, IConfiguration configuration)
    {
        _cache = cache;
        _configuration = configuration;
    }

    public Task<string> RegisterClient(string clientName, List<string> redirectUris, string? requestedScopes)
    {
        // Generate a new proxy client ID
        var proxyClientId = Guid.NewGuid().ToString();

        // Get the real Entra ID app registration details from configuration
        var entraClientId = _configuration["AzureAd:ClientId"] 
            ?? throw new InvalidOperationException("AzureAd:ClientId not configured");
        var entraTenantId = _configuration["AzureAd:TenantId"] 
            ?? throw new InvalidOperationException("AzureAd:TenantId not configured");

        var mapping = new ClientMapping
        {
            ProxyClientId = proxyClientId,
            EntraClientId = entraClientId,
            EntaTenantId = entraTenantId,
            RedirectUris = redirectUris,
            RequestedScopes = requestedScopes,
            ClientName = clientName,
            CreatedAt = DateTime.UtcNow
        };

        // Store in cache
        var cacheKey = $"client:{proxyClientId}";
        _cache.Set(cacheKey, mapping, TimeSpan.FromHours(CLIENT_EXPIRATION_HOURS));

        return Task.FromResult(proxyClientId);
    }

    public Task<ClientMapping?> GetClientMapping(string proxyClientId)
    {
        var cacheKey = $"client:{proxyClientId}";
        _cache.TryGetValue<ClientMapping>(cacheKey, out var mapping);
        return Task.FromResult(mapping);
    }
}
