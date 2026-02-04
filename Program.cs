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
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
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

// Configure cookie settings - Session Management
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Session timeout: 30 minutes
    options.SlidingExpiration = true; // Reset timeout on activity
    options.Cookie.HttpOnly = true; // Prevent XSS attacks
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Use HTTPS in production
    options.Cookie.SameSite = SameSiteMode.Strict; // CSRF protection
});

// Configure Session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Session timeout
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

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession(); // Enable session middleware

// Session timeout middleware - must be after UseSession but before UseAuthentication
app.UseMiddleware<SecureWebApp.Middleware.SessionTimeoutMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

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
