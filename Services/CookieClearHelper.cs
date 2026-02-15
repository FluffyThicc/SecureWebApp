using Microsoft.AspNetCore.Http;

namespace SecureWebApp.Services;

/// <summary>
/// Helpers to delete Identity and Session cookies.
/// Use the same options as when the cookies were set so the browser removes them.
/// Path /, HttpOnly, SameSite, Secure from request.
/// </summary>
public static class CookieClearHelper
{
    private static CookieOptions GetOptions(HttpContext context) => new()
    {
        Path = "/",
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = context.Request.IsHttps
    };

    public static void ClearSessionCookie(HttpContext context)
    {
        context.Response.Cookies.Delete(".AspNetCore.Session", GetOptions(context));
    }

    public static void ClearAuthCookie(HttpContext context)
    {
        context.Response.Cookies.Delete(".AspNetCore.Identity.Application", GetOptions(context));
    }

    /// <summary>
    /// Cookie name used when the server redirects to Login after session timeout or invalidation.
    /// Login action only performs sign-out when this cookie is present (avoids user-controlled bypass).
    /// </summary>
    public const string ForcedLogoutReasonCookieName = "SWA.ForcedLogoutReason";

    /// <summary>
    /// Sets a short-lived cookie so Login GET can recognise a server-initiated forced logout (CWE-247).
    /// Only the server sets this when redirecting from middleware or OnValidatePrincipal.
    /// </summary>
    public static void SetForcedLogoutReasonCookie(HttpContext context, string value)
    {
        context.Response.Cookies.Append(ForcedLogoutReasonCookieName, value, new CookieOptions
        {
            Path = "/Account",
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = context.Request.IsHttps,
            MaxAge = TimeSpan.FromSeconds(60),
            IsEssential = true
        });
    }
}
