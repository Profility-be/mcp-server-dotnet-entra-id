using System.ComponentModel;
using System.Security.Claims;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Profility.MCP.Internal.Tools;

/// <summary>
/// WhoAmI tool - Returns the authenticated user's information from Entra ID claims.
/// This tool proves that OAuth authentication is working correctly.
/// </summary>
[McpServerToolType]
public class WhoAmITool
{
    /// <summary>
    /// The result of the WhoAmI tool. Returning a typed object instead of a formatted string
    /// makes the SDK publish an outputSchema for the tool and emit structured content, so the
    /// client can consume the fields directly instead of parsing prose.
    /// </summary>
    /// <param name="Authenticated">Whether the caller presented a valid token.</param>
    /// <param name="Name">Display name from the token.</param>
    /// <param name="Email">Email address from the token.</param>
    /// <param name="UserId">Entra ID object identifier (oid) of the user.</param>
    /// <param name="Upn">User principal name.</param>
    /// <param name="Claims">Every claim present in the token, keyed by claim type.</param>
    public record WhoAmIResult(
        bool Authenticated,
        string Name,
        string Email,
        string UserId,
        string Upn,
        IReadOnlyDictionary<string, string[]> Claims);

    // Note for anyone migrating from an earlier version of this template: this tool used to take
    // an IHttpContextAccessor and read HttpContext.User. Prefer RequestContext<T>.User - it is
    // transport-agnostic and correct in every session mode, whereas the HttpContext of the request
    // that started a stateful session has already completed by the time a tool runs on it.
    [McpServerTool(
        Title = "Who am I?",
        ReadOnly = true,
        Idempotent = true,
        OpenWorld = false,
        UseStructuredContent = true)]
    // Keep this wording. The more literal description below reads as credential harvesting to
    // Claude's connector review and triggers a "Connector is not safe" error.
    [Description("Returns general session context for the authenticated account so the assistant knows which tenant it is operating under.")]
    //[Description("Get information about the currently authenticated user (name, email, ID, etc.)")]
    public WhoAmIResult WhoAmI(RequestContext<CallToolRequestParams> context)
    {
        var user = context.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            throw new McpException("No authenticated user found. OAuth authentication may have failed.");
        }

        // Extract common Entra ID claims. Entra hands out both the short OIDC claim names and the
        // long SOAP-era ClaimTypes URIs depending on the token, so check both.
        string Claim(string primary, params string[] fallbacks) =>
            user.FindFirst(primary)?.Value
            ?? fallbacks.Select(type => user.FindFirst(type)?.Value).FirstOrDefault(value => value is not null)
            ?? "Unknown";

        var claims = user.Claims
            .GroupBy(claim => claim.Type)
            .ToDictionary(group => group.Key, group => group.Select(claim => claim.Value).ToArray());

        return new WhoAmIResult(
            Authenticated: true,
            Name: Claim(ClaimTypes.Name, "name", "preferred_username"),
            Email: Claim(ClaimTypes.Email, "email", "preferred_username"),
            UserId: Claim(ClaimTypes.NameIdentifier, "sub", "oid"),
            Upn: Claim(ClaimTypes.Upn, "upn", "preferred_username"),
            Claims: claims);
    }
}
