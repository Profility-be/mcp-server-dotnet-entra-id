using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace MCP.Services.Jwt;

public class SampleClaimProvider : IClaimProvider
{
    public void AddClaims(List<Claim> claims, ClaimProviderContext context)
    {
        claims.Add(new Claim("custom_claim", "custom_value"));
    }
}