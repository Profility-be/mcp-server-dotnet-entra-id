using MCP.Models;
using System.Collections.Concurrent;

namespace MCP.Services;

/// <summary>
/// Manages temporary single-use login tokens for the custom login page flow.
/// Uses static dictionary like InMemoryTokenStore.
/// </summary>
public interface ILoginTokenStore
{
    Task<string> CreateLoginToken(string encryptedState);
    Task<LoginTokenData?> GetAndConsumeLoginToken(string token);
}

public class InMemoryLoginTokenStore : ILoginTokenStore
{
    private static readonly ConcurrentDictionary<string, LoginTokenData> _loginTokens = new();
    private const int LOGIN_TOKEN_EXPIRATION_MINUTES = 10;

    public Task<string> CreateLoginToken(string encryptedState)
    {
        var token = Guid.NewGuid().ToString("N");
        
        var loginData = new LoginTokenData
        {
            Token = token,
            EncryptedState = encryptedState,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(LOGIN_TOKEN_EXPIRATION_MINUTES)
        };

        _loginTokens[token] = loginData;
        return Task.FromResult(token);
    }

    public Task<LoginTokenData?> GetAndConsumeLoginToken(string token)
    {
        if (!_loginTokens.TryRemove(token, out var loginData)) { return Task.FromResult<LoginTokenData?>(null); }
        
        if (loginData.ExpiresAt < DateTime.UtcNow) { return Task.FromResult<LoginTokenData?>(null); }

        return Task.FromResult<LoginTokenData?>(loginData);
    }
}
