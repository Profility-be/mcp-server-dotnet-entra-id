using System.ComponentModel;
using System.Security.Claims;
using System.Text;
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
    // Claims are filtered with an allowlist, not a denylist: whatever Entra ID or a custom
    // IClaimProvider adds later stays hidden until someone opts it in here. Note that JwtBearer maps
    // some claims to the long ClaimTypes URI and leaves others short, so both spellings are listed.
    private static readonly HashSet<string> AllowedClaims = new(StringComparer.OrdinalIgnoreCase)
    {
        "name", ClaimTypes.Name,
        "email", ClaimTypes.Email,
        "given_name", ClaimTypes.GivenName,
        "family_name", ClaimTypes.Surname,
        "upn", ClaimTypes.Upn,
        "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier",
        "tid", "http://schemas.microsoft.com/identity/claims/tenantid",
        "scope", "client_id", "jti", "iss", "aud",
    };

    [McpServerTool(Title = "Who am I?", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    // Keep this wording. The more literal description below reads as credential harvesting to
    // Claude's connector review and triggers a "Connector is not safe" error.
    [Description("Returns general session context for the authenticated account so the assistant knows which tenant it is operating under.")]
    public string WhoAmI(RequestContext<CallToolRequestParams> context)
    {
        // Prefer RequestContext.User over IHttpContextAccessor: it is correct in every session mode,
        // whereas in a stateful session the tool runs after the originating request has completed.
        var user = context.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            throw new McpException("No authenticated user found. OAuth authentication may have failed.");
        }

        // Entra hands out both the short OIDC claim names and the long ClaimTypes URIs depending on
        // the token, so try each in turn.
        string Claim(params string[] types) =>
            types.Select(type => user.FindFirst(type)?.Value).FirstOrDefault(value => value is not null)
            ?? "Unknown";

        var shown = user.Claims
            .Where(claim => AllowedClaims.Contains(claim.Type) && claim.Value.Length <= 256)
            .OrderBy(claim => claim.Type)
            .ToList();

        var result = new StringBuilder();
        result.AppendLine("Authenticated via Entra ID OAuth.");
        result.AppendLine();
        result.AppendLine($"Name:  {Claim(ClaimTypes.Name, "name", "preferred_username")}");
        result.AppendLine($"Email: {Claim(ClaimTypes.Email, "email", "preferred_username")}");
        result.AppendLine($"OID:   {Claim(ClaimTypes.NameIdentifier, "sub", "oid")}");
        result.AppendLine($"UPN:   {Claim(ClaimTypes.Upn, "upn", "preferred_username")}");

        if (long.TryParse(user.FindFirst("exp")?.Value, out var expUnixSeconds))
        {
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expUnixSeconds);
            var secondsLeft = (long)Math.Max(0, (expiresAt - DateTimeOffset.UtcNow).TotalSeconds);
            result.AppendLine($"Token expires: {expiresAt:u} ({secondsLeft}s left)");
        }

        result.AppendLine();
        result.AppendLine($"Claims ({shown.Count} shown, {user.Claims.Count() - shown.Count} withheld):");
        foreach (var claim in shown)
        {
            result.AppendLine($"  {claim.Type}: {claim.Value}");
        }

        return result.ToString();
    }
}
