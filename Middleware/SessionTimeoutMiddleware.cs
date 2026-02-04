using SecureWebApp.Data;
using SecureWebApp.Models;
using Microsoft.AspNetCore.Identity;

namespace SecureWebApp.Middleware;

public class SessionTimeoutMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SessionTimeoutMiddleware> _logger;

    public SessionTimeoutMiddleware(RequestDelegate next, ILogger<SessionTimeoutMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IServiceProvider serviceProvider)
    {
        // Skip session check for login/register pages and static files
        var path = context.Request.Path.Value?.ToLower();
        if (path?.Contains("/account/login") == true || 
            path?.Contains("/account/register") == true ||
            path?.Contains("/account/logout") == true ||
            path?.StartsWith("/lib/") == true ||
            path?.StartsWith("/css/") == true ||
            path?.StartsWith("/js/") == true ||
            path?.StartsWith("/uploads/") == true)
        {
            await _next(context);
            return;
        }

        // Check if user is authenticated
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var sessionId = context.Session.GetString("SessionId");
            var loginTimeStr = context.Session.GetString("LoginTime");

            // If session data is missing, redirect to login
            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(loginTimeStr))
            {
                _logger.LogWarning("Session timeout detected for user. Redirecting to login.");
                context.Session.Clear();
                
                using (var scope = serviceProvider.CreateScope())
                {
                    var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();
                    await signInManager.SignOutAsync();
                }
                
                context.Response.Redirect("/Account/Login?timeout=true");
                return;
            }

            // Check session timeout (30 minutes)
            if (DateTime.TryParse(loginTimeStr, out var loginTime))
            {
                var sessionTimeout = TimeSpan.FromMinutes(30);
                var elapsed = DateTime.UtcNow - loginTime.ToUniversalTime();

                if (elapsed > sessionTimeout)
                {
                    var userId = context.Session.GetString("UserId");
                    
                    // Log session timeout
                    try
                    {
                        using (var scope = serviceProvider.CreateScope())
                        {
                            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                            var auditLog = new AuditLog
                            {
                                UserId = userId ?? "",
                                Action = "SessionTimeout",
                                Description = "Session expired due to inactivity",
                                IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                                UserAgent = context.Request.Headers["User-Agent"].ToString(),
                                SessionId = sessionId,
                                Timestamp = DateTime.UtcNow,
                                IsSuccess = false,
                                FailureReason = "Session timeout (30 minutes)"
                            };
                            dbContext.AuditLogs.Add(auditLog);
                            await dbContext.SaveChangesAsync();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to log session timeout");
                    }

                    _logger.LogWarning("Session timeout for user {UserId}. Session duration: {Elapsed}", userId, elapsed);
                    context.Session.Clear();
                    
                    using (var scope = serviceProvider.CreateScope())
                    {
                        var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();
                        await signInManager.SignOutAsync();
                    }
                    
                    context.Response.Redirect("/Account/Login?timeout=true");
                    return;
                }

                // Update last activity time (sliding expiration)
                context.Session.SetString("LoginTime", DateTime.UtcNow.ToString("O"));
            }
        }

        await _next(context);
    }
}

