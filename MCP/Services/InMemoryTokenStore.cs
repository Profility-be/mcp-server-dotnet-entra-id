using Microsoft.Extensions.Caching.Memory;
using MCP.Models;

namespace MCP.Services;

/// <summary>
/// In-memory store for mapping proxy tokens to Entra ID tokens.
/// Implements the Phantom Token Pattern.
/// </summary>
public interface ITokenStore
{
    Task StoreTokenMapping(TokenMapping mapping);
    Task<TokenMapping?> GetTokenMapping(string proxyAccessToken);
    Task<TokenMapping?> GetTokenMappingByCode(string authorizationCode);
    Task RemoveTokenMapping(string proxyAccessToken);
    Task<bool> ValidateAndConsumeAuthorizationCode(string code);
    Task StoreAuthorizationCode(string code, PkceStateData stateData, string entraAuthCode);
}

public class InMemoryTokenStore : ITokenStore
{
    private readonly IMemoryCache _cache;
    private const int TOKEN_EXPIRATION_HOURS = 1;
    private const int AUTH_CODE_EXPIRATION_MINUTES = 5;

    public InMemoryTokenStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public Task StoreTokenMapping(TokenMapping mapping)
    {
        var cacheKey = $"token:{mapping.ProxyAccessToken}";
        var expiration = mapping.ExpiresAt - DateTime.UtcNow;
        
        if (expiration <= TimeSpan.Zero)
        {
            expiration = TimeSpan.FromHours(TOKEN_EXPIRATION_HOURS);
        }

        _cache.Set(cacheKey, mapping, expiration);

        // Also store by authorization code for token exchange lookup
        var codeCacheKey = $"token_by_code:{mapping.AuthorizationCode}";
        _cache.Set(codeCacheKey, mapping, TimeSpan.FromMinutes(AUTH_CODE_EXPIRATION_MINUTES));

        return Task.CompletedTask;
    }

    public Task<TokenMapping?> GetTokenMapping(string proxyAccessToken)
    {
        var cacheKey = $"token:{proxyAccessToken}";
        _cache.TryGetValue<TokenMapping>(cacheKey, out var mapping);
        return Task.FromResult(mapping);
    }

    public Task<TokenMapping?> GetTokenMappingByCode(string authorizationCode)
    {
        var cacheKey = $"token_by_code:{authorizationCode}";
        _cache.TryGetValue<TokenMapping>(cacheKey, out var mapping);
        return Task.FromResult(mapping);
    }

    public Task RemoveTokenMapping(string proxyAccessToken)
    {
        var cacheKey = $"token:{proxyAccessToken}";
        _cache.Remove(cacheKey);
        return Task.CompletedTask;
    }

    public Task<bool> ValidateAndConsumeAuthorizationCode(string code)
    {
        var cacheKey = $"auth_code:{code}";
        
        if (_cache.TryGetValue<bool>(cacheKey, out var exists))
        {
            // Code already used
            return Task.FromResult(false);
        }

        // Mark code as used (store for 5 minutes to prevent replay)
        _cache.Set(cacheKey, true, TimeSpan.FromMinutes(AUTH_CODE_EXPIRATION_MINUTES));
        return Task.FromResult(true);
    }

    public Task StoreAuthorizationCode(string code, PkceStateData stateData, string entraAuthCode)
    {
        var cacheKey = $"auth_code_data:{code}";
        var data = new AuthorizationCodeData
        {
            ProxyCode = code,
            EntraAuthCode = entraAuthCode,
            StateData = stateData,
            CreatedAt = DateTime.UtcNow
        };

        _cache.Set(cacheKey, data, TimeSpan.FromMinutes(AUTH_CODE_EXPIRATION_MINUTES));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Internal class to store authorization code data
/// </summary>
internal class AuthorizationCodeData
{
    public required string ProxyCode { get; set; }
    public required string EntraAuthCode { get; set; }
    public required PkceStateData StateData { get; set; }
    public DateTime CreatedAt { get; set; }
}
