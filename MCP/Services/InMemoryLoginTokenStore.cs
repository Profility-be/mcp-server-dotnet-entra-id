using Microsoft.Extensions.Caching.Memory;
using MCP.Models;

namespace MCP.Services;

/// <summary>
/// Manages temporary login tokens for the custom login page flow.
/// </summary>
public interface ILoginTokenStore
{
    Task<string> CreateLoginToken(string encryptedState);
    Task<LoginTokenData?> GetLoginTokenData(string token);
    Task MarkTokenAsUsed(string token);
    Task RemoveLoginToken(string token);
}

public class InMemoryLoginTokenStore : ILoginTokenStore
{
    private readonly IMemoryCache _cache;
    private const int LOGIN_TOKEN_EXPIRATION_MINUTES = 10;

    public InMemoryLoginTokenStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public Task<string> CreateLoginToken(string encryptedState)
    {
        var token = Guid.NewGuid().ToString("N"); // 32 character hex string
        
        var loginData = new LoginTokenData
        {
            Token = token,
            EncryptedState = encryptedState,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(LOGIN_TOKEN_EXPIRATION_MINUTES),
            IsUsed = false
        };

        var cacheKey = $"login_token:{token}";
        _cache.Set(cacheKey, loginData, TimeSpan.FromMinutes(LOGIN_TOKEN_EXPIRATION_MINUTES));

        return Task.FromResult(token);
    }

    public Task<LoginTokenData?> GetLoginTokenData(string token)
    {
        var cacheKey = $"login_token:{token}";
        _cache.TryGetValue<LoginTokenData>(cacheKey, out var data);

        // Check if expired
        if (data != null && data.ExpiresAt < DateTime.UtcNow)
        {
            _cache.Remove(cacheKey);
            return Task.FromResult<LoginTokenData?>(null);
        }

        return Task.FromResult(data);
    }

    public Task MarkTokenAsUsed(string token)
    {
        var cacheKey = $"login_token:{token}";
        if (_cache.TryGetValue<LoginTokenData>(cacheKey, out var data) && data != null)
        {
            data.IsUsed = true;
            _cache.Set(cacheKey, data, TimeSpan.FromMinutes(LOGIN_TOKEN_EXPIRATION_MINUTES));
        }
        return Task.CompletedTask;
    }

    public Task RemoveLoginToken(string token)
    {
        var cacheKey = $"login_token:{token}";
        _cache.Remove(cacheKey);
        return Task.CompletedTask;
    }
}
