using System.ComponentModel;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol.Server;

namespace Profility.MCP.Internal.Tools;

/// <summary>
/// WhoAmI tool - Returns the authenticated user's information from Entra ID claims.
/// This tool proves that OAuth authentication is working correctly.
/// </summary>
[McpServerToolType]
public class WhoAmITool
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public WhoAmITool(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    [McpServerTool]
    [Description("Get information about the currently authenticated user (name, email, ID, etc.)")]
    public string WhoAmI()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            return "❌ Error: No HTTP context available";
        }

        var user = httpContext.User;
        if (user == null || !user.Identity?.IsAuthenticated == true)
        {
            return "❌ Error: No authenticated user found. OAuth authentication may have failed.";
        }

        // Extract common Entra ID claims
        var claims = user.Claims.ToList();
        
        var name = user.FindFirst(ClaimTypes.Name)?.Value 
                   ?? user.FindFirst("name")?.Value 
                   ?? user.FindFirst("preferred_username")?.Value
                   ?? "Unknown";
        
        var email = user.FindFirst(ClaimTypes.Email)?.Value 
                    ?? user.FindFirst("email")?.Value
                    ?? user.FindFirst("preferred_username")?.Value
                    ?? "No email";
        
        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value 
                     ?? user.FindFirst("sub")?.Value
                     ?? user.FindFirst("oid")?.Value
                     ?? "Unknown";
        
        var upn = user.FindFirst(ClaimTypes.Upn)?.Value 
                  ?? user.FindFirst("upn")?.Value 
                  ?? user.FindFirst("preferred_username")?.Value
                  ?? "Not available";

        // Build response
        var result = $@"👤 **Who Am I?**

✅ **Authentication Status**: Authenticated via Entra ID OAuth

📋 **User Information**:
  • Name: {name}
  • Email: {email}
  • User ID (OID): {userId}
  • UPN: {upn}

🔐 **All Claims** ({claims.Count} total):
";

        foreach (var claim in claims.OrderBy(c => c.Type))
        {
            result += $"  • {claim.Type}: {claim.Value}\n";
        }

        result += $"\n✨ **OAuth Flow**: Working correctly! You are authenticated via Profility MCP OAuth Proxy.\n";

        return result;
    }
}
