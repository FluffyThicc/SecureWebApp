using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureWebApp.Models;
using SecureWebApp.Services;

namespace SecureWebApp.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly EncryptionService _encryptionService;

    public HomeController(
        ILogger<HomeController> logger,
        UserManager<ApplicationUser> userManager,
        EncryptionService encryptionService)
    {
        _logger = logger;
        _userManager = userManager;
        _encryptionService = encryptionService;
    }

    [Authorize]
    public async Task<IActionResult> Index()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
                ViewBag.UserInfo = new
                {
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    Gender = user.Gender,
                    DateOfBirth = user.DateOfBirth.ToString("yyyy-MM-dd"),
                    NRIC = _encryptionService.Decrypt(user.EncryptedNRIC),
                    WhoAmI = user.WhoAmI,
                    ResumeFileName = user.ResumeFileName
                };
                ViewBag.IsTwoFactorEnabled = isTwoFactorEnabled;
            }
        }
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    /// <summary>
    /// Custom handler for HTTP status codes such as 404 (Not Found) and 500 (Server Error).
    /// Provides user-friendly error pages instead of default server responses.
    /// </summary>
    /// <param name="code">HTTP status code (e.g. 404, 500).</param>
    [Route("Home/StatusCode")]
    public IActionResult StatusCode(int code)
    {
        // Log the status code for observability
        _logger.LogWarning("HTTP status code {StatusCode} returned for request {Path}", code, HttpContext.Request.Path);

        ViewBag.StatusCode = code;

        // Use a friendly message based on common status codes
        ViewBag.StatusMessage = code switch
        {
            404 => "The page you are looking for could not be found.",
            403 => "You do not have permission to access this resource.",
            500 => "An unexpected error occurred on the server.",
            _ => "An unexpected error occurred while processing your request."
        };

        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
