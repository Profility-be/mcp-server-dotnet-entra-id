using MCP.Models;

namespace Profility.MCP.Services.TokenStore;

/// <summary>
/// Interface for token storage implementations.
/// Both authorization_code and refresh_token flows use single-use codes.
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
