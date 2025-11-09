using MCP.Models;
using System.Collections.Concurrent;

namespace MCP.Services;

/// <summary>
/// In-memory store for single-use codes.
/// Both authorization_code and refresh_token flows use single-use codes.
/// Uses static dictionary for long-lived tokens (90 days).
/// </summary>
public interface ITokenStore
{
    /// <summary>
    /// Store code data (used for both initial auth and refresh flows)
    /// </summary>
    Task StoreCodeData(TokenData codeData);
    
    /// <summary>
    /// Get and consume code data (single-use)
    /// Returns null if code is invalid, expired, or already used
    /// </summary>
    Task<TokenData?> GetAndConsumeCode(string code);
}

public class InMemoryTokenStore : ITokenStore
{
    private static readonly ConcurrentDictionary<string, TokenData> _tokens = new();
    private const int TOKEN_EXPIRATION_DAYS = 90;

    public Task StoreCodeData(TokenData codeData)
    {
        codeData.CreatedAt = DateTime.UtcNow;
        _tokens[codeData.Code] = codeData;
        return Task.CompletedTask;
    }

    public Task<TokenData?> GetAndConsumeCode(string code)
    {
        if (!_tokens.TryRemove(code, out var tokenData)) { return Task.FromResult<TokenData?>(null); }
        
        // Check expiration (90 days)
        if (tokenData.CreatedAt.AddDays(TOKEN_EXPIRATION_DAYS) < DateTime.UtcNow) { return Task.FromResult<TokenData?>(null); }

        return Task.FromResult<TokenData?>(tokenData);
    }
}
