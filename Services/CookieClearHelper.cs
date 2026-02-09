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
}
