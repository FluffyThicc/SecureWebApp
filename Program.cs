using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Data;
using SecureWebApp.Models;
using SecureWebApp.Services;
using DotNetEnv;

// Load .env file if it exists
var envPath = Path.Combine(Directory.GetCurrentDirectory(), ".env");
if (File.Exists(envPath))
{
    Env.Load(envPath);
}

var builder = WebApplication.CreateBuilder(args);

// Load environment variables into configuration
builder.Configuration.AddEnvironmentVariables();

// Add services to the container.

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
// ^^ Gets connectiong string in appsettings.json


//Connect my app to the database using Entity Framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));


// adding identities to the user, for registration criteria 
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings - Strong password requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12; // Minimum 12 characters as per requirements
    
    // Lockout settings - Rate limiting after 3 failures
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3; // Lockout after 3 login failures
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false; // Set to true in production with email confirmation
    
    // Token settings
    options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
.AddEntityFrameworkStores<ApplicationDbContext>() // Saves details into the database
.AddDefaultTokenProviders(); // Includes authenticator token provider for Google Authenticator (TOTP) support

// Custom claims factory to add CurrentSessionToken to cookie for single active session validation
builder.Services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, SessionTokenClaimsPrincipalFactory>();

// Helper to explicitly clear auth cookie (used when SignOutAsync doesn't clear it reliably)
static void ClearAuthCookie(HttpContext context)
{
    // Use OnStarting so the delete runs right before response is sent (ensures it isn't overwritten)
    context.Response.OnStarting(() =>
    {
        context.Response.Cookies.Delete(".AspNetCore.Identity.Application", new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Strict
        });
        return Task.CompletedTask;
    });
}

// Configure cookie settings - Session Management
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(1); // Session timeout: 1 minute
    options.SlidingExpiration = true; // Reset timeout on activity
    options.Cookie.HttpOnly = true; // Prevent XSS attacks
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Use HTTPS in production
    options.Cookie.SameSite = SameSiteMode.Strict; // CSRF protection

    // Single active session: validate session token on every request. If token mismatch (logged in elsewhere), reject and sign out.
    options.Events.OnValidatePrincipal = async context =>
    {
        if (context.Principal?.Identity?.IsAuthenticated != true) return;

        var sessionTokenClaim = context.Principal.FindFirst("SessionToken")?.Value;
        var userId = context.Principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? context.Principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

        if (string.IsNullOrEmpty(userId)) return;

        var scope = context.HttpContext.RequestServices.CreateScope();
        try
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var user = await dbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null) { context.RejectPrincipal(); await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme); context.HttpContext.Session.Clear(); ClearAuthCookie(context.HttpContext); context.HttpContext.Response.Redirect("/Account/Login?sessionInvalidated=1"); return; }

            var dbToken = user.CurrentSessionToken;
            if (string.IsNullOrEmpty(dbToken) || sessionTokenClaim != dbToken)
            {
                var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
                logger.LogWarning("Session token mismatch for user {UserId}. Forcing logout (logged in elsewhere).", userId);
                dbContext.AuditLogs.Add(new AuditLog { UserId = userId, Action = "SessionInvalidated", Description = "Forced logout due to session token mismatch (logged in elsewhere)", IsSuccess = false, Timestamp = DateTime.UtcNow });
                await dbContext.SaveChangesAsync();
                context.RejectPrincipal();
                await signInManager.SignOutAsync();
                context.HttpContext.Session.Clear();
                ClearAuthCookie(context.HttpContext);
                context.HttpContext.Response.Redirect("/Account/Login?sessionInvalidated=1");
            }
        }
        finally { scope.Dispose(); }
    };
});

// Configure Session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1); // Session timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Add custom services
builder.Services.AddScoped<EncryptionService>();
builder.Services.AddHttpClient<RecaptchaService>();
builder.Services.AddScoped<RecaptchaService>();
builder.Services.AddScoped<IEmailSender, EmailSender>();

// Add security headers
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(60);
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Security headers (use indexer to avoid ArgumentException on duplicate keys)
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    await next();
});

// Only redirect to HTTPS in production (in Development, app may run HTTP-only)
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}
app.UseStaticFiles();

app.UseRouting();

app.UseSession(); // Enable session middleware

app.UseAuthentication();
app.UseAuthorization();

// Session timeout middleware - must run after UseAuthentication so User is populated for the session check
app.UseMiddleware<SecureWebApp.Middleware.SessionTimeoutMiddleware>();

// Handle status code pages (e.g. 404, 500) with a friendly, custom page
app.UseStatusCodePagesWithReExecute("/Home/StatusCode", "?code={0}");

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

// Apply database migrations and create default roles
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        // Apply pending migrations instead of EnsureCreated
        context.Database.Migrate();
        
        // Create default roles if needed (optional)
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        if (!await roleManager.RoleExistsAsync("Member"))
        {
            await roleManager.CreateAsync(new IdentityRole("Member"));
        }
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred applying migrations or creating roles.");
    }
}

app.Run();
