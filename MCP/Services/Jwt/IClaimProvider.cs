using System.Security.Claims;
using MCP.Controllers; // For UserClaims

namespace MCP.Services.Jwt;

/// <summary>
/// Interface for providers that can add custom claims to JWT tokens.
/// Providers are executed in registration order, allowing chaining (later providers can build on claims from earlier ones).
/// </summary>
public interface IClaimProvider
{
    /// <summary>
    /// Adds claims to the existing list. Can inspect/modify existing claims for chaining.
    /// </summary>
    /// <param name="claims">The current list of claims (mutable, so add/remove as needed).</param>
    /// <param name="context">Context with relevant data for claim generation.</param>
    void AddClaims(List<Claim> claims, ClaimProviderContext context);
}

/// <summary>
/// Context passed to claim providers, containing data from the token generation process.
/// </summary>
public class ClaimProviderContext
{
    public string ClientId { get; set; } = string.Empty;
    public string UserIdentifier { get; set; } = string.Empty;
    public string McpServerUrl { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public UserClaims? EntraIDUserClaims { get; set; }
}