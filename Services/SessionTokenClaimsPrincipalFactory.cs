using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SecureWebApp.Models;

namespace SecureWebApp.Services;

/// <summary>
/// Adds CurrentSessionToken to user claims so it can be validated on each request (OnValidatePrincipal).
/// Enables single active session per user across different browsers/devices.
/// </summary>
public class SessionTokenClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>
{
    public SessionTokenClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<IdentityOptions> options)
        : base(userManager, roleManager, options)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        if (!string.IsNullOrEmpty(user.CurrentSessionToken))
        {
            identity.AddClaim(new Claim("SessionToken", user.CurrentSessionToken));
        }

        return identity;
    }
}
