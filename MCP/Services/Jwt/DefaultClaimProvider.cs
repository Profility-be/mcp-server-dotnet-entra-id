using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace MCP.Services.Jwt;

/// <summary>
/// Default claim provider - adds standard Entra ID user claims to JWT tokens.
/// If modifications are needed, create a new claim provider and register it after this one to enable chaining.
/// </summary>
public class DefaultClaimProvider : IClaimProvider
{
    public void AddClaims(List<Claim> claims, ClaimProviderContext context)
    {
        // Add user claims from Entra ID token if available
        if (context.EntraIDUserClaims != null)
        {
            var userClaims = context.EntraIDUserClaims;

            if (!string.IsNullOrEmpty(userClaims.Name))
                claims.Add(new Claim(JwtRegisteredClaimNames.Name, userClaims.Name));

            if (!string.IsNullOrEmpty(userClaims.Email))
                claims.Add(new Claim(JwtRegisteredClaimNames.Email, userClaims.Email));

            if (!string.IsNullOrEmpty(userClaims.GivenName))
                claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, userClaims.GivenName));

            if (!string.IsNullOrEmpty(userClaims.FamilyName))
                claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, userClaims.FamilyName));

            if (!string.IsNullOrEmpty(userClaims.ObjectId))
                claims.Add(new Claim("oid", userClaims.ObjectId));

            if (!string.IsNullOrEmpty(userClaims.PreferredUsername))
                claims.Add(new Claim("preferred_username", userClaims.PreferredUsername));

            if (!string.IsNullOrEmpty(userClaims.Upn))
                claims.Add(new Claim("upn", userClaims.Upn));

            if (!string.IsNullOrEmpty(userClaims.TenantId))
                claims.Add(new Claim("tid", userClaims.TenantId));
        }
    }
}