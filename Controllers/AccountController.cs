    using System.Net;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.EntityFrameworkCore;
    using SecureWebApp.Models;
    using SecureWebApp.Services;
    using SecureWebApp.Data;

    namespace SecureWebApp.Controllers;

    public class AccountController : Controller
    {

        //This declares the tools that the controller will need later.
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly EncryptionService _encryptionService; // encrpytion service used 
        private readonly IWebHostEnvironment _environment; // tells you where wwwroot folder is (needed for saving resume files)
        private readonly ApplicationDbContext _context; // Database context for audit logging and password history
        private readonly RecaptchaService _recaptchaService; // reCAPTCHA verification service
        private readonly IEmailSender _emailSender; // Email sender for password reset and 2FA

        // Password policy settings (for demo, values kept small so they are easy to test)
        private const int PasswordHistoryDepth = 2; // Avoid reuse of last 2 passwords
        private static readonly TimeSpan PasswordMinimumAge = TimeSpan.FromMinutes(1); // Cannot change again within 1 minute
        private static readonly TimeSpan PasswordMaximumAge = TimeSpan.FromMinutes(10); // Should change after 10 minutes

        // Constuctor helps give the tools, its like telling 
        // ASP.NET Give me the tools and services that is built it already
        //  and assign to the variables I declare above 
        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<AccountController> logger,
            EncryptionService encryptionService,
            IWebHostEnvironment environment,
            ApplicationDbContext context,
            RecaptchaService recaptchaService,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _encryptionService = encryptionService;
            _environment = environment;
            _context = context;
            _recaptchaService = recaptchaService;
            _emailSender = emailSender;
        }

        [HttpGet]
        public IActionResult Register()
        {
            ViewBag.RecaptchaSiteKey = _recaptchaService.GetSiteKey();
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // Always provide the reCAPTCHA site key to the view (even when returning with validation errors)
            ViewBag.RecaptchaSiteKey = _recaptchaService.GetSiteKey();

            // Server-side password strength validation
            if (!string.IsNullOrEmpty(model.Password))
            {
                ValidatePasswordStrength(model.Password, nameof(model.Password));
            }

            //checks if the model registered has all the fields entered properly that is set to required
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Verify reCAPTCHA token
            var recaptchaToken = Request.Form["g-recaptcha-response"].ToString();
            var remoteIpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var isRecaptchaValid = await _recaptchaService.VerifyTokenAsync(recaptchaToken, remoteIpAddress);
            
            if (!isRecaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                await LogAuditActivity("", "Register", $"reCAPTCHA verification failed for email: {model.Email}", false, 
                    remoteIpAddress, Request.Headers["User-Agent"].ToString(), failureReason: "reCAPTCHA verification failed");
                return View(model);
            }

            // Check if email already exists (case-insensitive check)
            var normalizedEmail = _userManager.NormalizeEmail(model.Email);
            var existingUser = await _userManager.FindByEmailAsync(normalizedEmail);
            if (existingUser != null)
            {
                ModelState.AddModelError(nameof(model.Email), "This email address is already registered. Please use a different email or try logging in.");
                _logger.LogWarning("Registration attempt with existing email: {Email}", model.Email);
                return View(model);
            }

            // Double-check by username as well (since we use email as username)
            var existingUserByUsername = await _userManager.FindByNameAsync(model.Email);
            if (existingUserByUsername != null)
            {
                ModelState.AddModelError(nameof(model.Email), "This email address is already registered. Please use a different email or try logging in.");
                _logger.LogWarning("Registration attempt with existing username (email): {Email}", model.Email);
                return View(model);
            }

            // Handle file upload
            string? resumeFilePath = null;
            string? resumeFileName = null;

            if (model.Resume != null && model.Resume.Length > 0)
            {
                // Create uploads directory if it doesn't exist
                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "resumes");
                if (!Directory.Exists(uploadsFolder))
                {
                    Directory.CreateDirectory(uploadsFolder);
                }

                // Use only the file name (no path) to prevent path traversal
                var originalFileName = Path.GetFileName(model.Resume.FileName);

                // Generate unique, safe filename
                var uniqueFileName = $"{Guid.NewGuid()}_{originalFileName}";
                resumeFileName = originalFileName;
                resumeFilePath = Path.Combine(uploadsFolder, uniqueFileName);

                // Save file
                using (var fileStream = new FileStream(resumeFilePath, FileMode.Create))
                {
                    await model.Resume.CopyToAsync(fileStream);
                }

                // Store relative path
                resumeFilePath = Path.Combine("uploads", "resumes", uniqueFileName);
            }

            // Encrypt NRIC
            var encryptedNRIC = _encryptionService.Encrypt(model.NRIC);

            // Create user
            var user = new ApplicationUser
            {
                UserName = model.Email, // Use email as username
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                Gender = model.Gender,
                EncryptedNRIC = encryptedNRIC,
                DateOfBirth = model.DateOfBirth,
                ResumeFilePath = resumeFilePath,
                ResumeFileName = resumeFileName,
                WhoAmI = WebUtility.HtmlEncode(model.WhoAmI ?? string.Empty),
                EmailConfirmed = false, // In production, you'd want email confirmation
                PasswordLastChangedAtUtc = DateTime.UtcNow
            };

            // Create user in database
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User successfully registered: {Email} (ID: {UserId})", user.Email, user.Id);
                
                // Verify user was saved to database by retrieving it
                var savedUser = await _userManager.FindByEmailAsync(user.Email);
                if (savedUser == null)
                {
                    _logger.LogError("User was not saved to database after creation. Email: {Email}", user.Email);
                    ModelState.AddModelError(string.Empty, "An error occurred during registration. Please try again.");
                    
                    // Clean up uploaded file
                    if (!string.IsNullOrEmpty(resumeFilePath))
                    {
                        var fullPath = Path.Combine(_environment.WebRootPath, resumeFilePath);
                        if (System.IO.File.Exists(fullPath))
                        {
                            System.IO.File.Delete(fullPath);
                        }
                    }
                    return View(model);
                }

                _logger.LogInformation("User successfully saved to database: {Email} (ID: {UserId})", savedUser.Email, savedUser.Id);

                // Initialise password history so that future changes can enforce reuse rules
                await SavePasswordHistoryAsync(savedUser);
                
                // Log registration activity to audit log
                await LogAuditActivity(savedUser.Id, "Register", "User registration successful", true);

                // Single active session: issue session token for new user
                var sessionToken = Guid.NewGuid().ToString();
                user.CurrentSessionToken = sessionToken;
                user.SessionIssuedAtUtc = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                HttpContext.Session.SetString("UserId", savedUser.Id);
                HttpContext.Session.SetString("SessionId", sessionToken);
                HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("O"));
                HttpContext.Session.SetString("UserAgent", Request.Headers["User-Agent"].ToString());

                await _signInManager.SignInAsync(user, isPersistent: false);
                
                return RedirectToAction("Index", "Home");
            }

            // If user creation failed, handle errors
            _logger.LogWarning("User creation failed for email: {Email}. Errors: {Errors}", 
                model.Email, string.Join(", ", result.Errors.Select(e => e.Description)));

            // Log failed registration attempt
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = Request.Headers["User-Agent"].ToString();
            await LogAuditActivity("", "Register", $"Registration failed for email: {model.Email}", false, 
                ipAddress, userAgent, failureReason: string.Join(", ", result.Errors.Select(e => e.Description)));

            foreach (var error in result.Errors)
            {
                // Check if it's a duplicate email error from Identity
                if (error.Code == "DuplicateUserName" || error.Code == "DuplicateEmail")
                {
                    ModelState.AddModelError(nameof(model.Email), "This email address is already registered. Please use a different email or try logging in.");
                }
                else
                {
                    // Map other Identity errors to appropriate fields
                    var fieldName = error.Code.Contains("Password") ? nameof(model.Password) : string.Empty;
                    ModelState.AddModelError(fieldName, error.Description);
                }
            }

            // Clean up uploaded file if user creation failed
            if (!string.IsNullOrEmpty(resumeFilePath))
            {
                var fullPath = Path.Combine(_environment.WebRootPath, resumeFilePath);
                if (System.IO.File.Exists(fullPath))
                {
                    System.IO.File.Delete(fullPath);
                }
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Login(string? returnUrl = null)
        {
            // Only perform sign-out when the server set the forced-logout cookie (CWE-247: avoid user-controlled bypass).
            // Middleware and OnValidatePrincipal set SWA.ForcedLogoutReason when redirecting after timeout/invalidation.
            var forcedLogoutReason = Request.Cookies[CookieClearHelper.ForcedLogoutReasonCookieName];
            var forcedLogout = !string.IsNullOrEmpty(forcedLogoutReason);

            if (forcedLogout)
            {
                if (User.Identity?.IsAuthenticated == true)
                    await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                CookieClearHelper.ClearSessionCookie(HttpContext);
                CookieClearHelper.ClearAuthCookie(HttpContext);
                if (forcedLogoutReason == "expired")
                    TempData["SessionExpired"] = "Your session has expired. Please login again.";
                else
                    TempData["SessionInvalidated"] = "You have been signed out because you logged in from another device or browser.";
                Response.Cookies.Delete(CookieClearHelper.ForcedLogoutReasonCookieName, new CookieOptions { Path = "/Account", HttpOnly = true, SameSite = SameSiteMode.Strict, Secure = Request.IsHttps });
            }
            else if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Index", "Home");
            }

            ViewBag.RecaptchaSiteKey = _recaptchaService.GetSiteKey();
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            returnUrl ??= model.ReturnUrl ?? Url.Content("~/");

            if (!ModelState.IsValid)
            {
                model.ReturnUrl = returnUrl;
                return View(model);
            }

            // Get IP Address and User Agent for audit logging
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = Request.Headers["User-Agent"].ToString();

            // Verify reCAPTCHA token (run before password check - token is single-use)
            var recaptchaToken = Request.Form["g-recaptcha-response"].ToString();
            var isRecaptchaValid = await _recaptchaService.VerifyTokenAsync(recaptchaToken, ipAddress);
            
            if (!isRecaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                await LogAuditActivity("", "Login", $"reCAPTCHA verification failed for email: {model.Email}", false, 
                    ipAddress, userAgent, failureReason: "reCAPTCHA verification failed");
                model.ReturnUrl = returnUrl;
                return View(model);
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Log failed login attempt
                await LogAuditActivity("", "Login", "Login attempt with invalid email", false, 
                    ipAddress, userAgent, failureReason: "Invalid email address");
                
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                model.ReturnUrl = returnUrl;
                return View(model);
            }

            // Attempt password verification with lockout support but without issuing auth cookie yet
            var passwordCheckResult = await _signInManager.CheckPasswordSignInAsync(
                user, model.Password, lockoutOnFailure: true);

            if (passwordCheckResult.Succeeded)
            {
                // Check if user has 2FA enabled with authenticator
                var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
                
                if (isTwoFactorEnabled)
                {
                    // User has 2FA enabled - require authenticator code
                    HttpContext.Session.SetString("2FA_UserId", user.Id);
                    HttpContext.Session.SetString("2FA_RememberMe", model.RememberMe.ToString());
                    HttpContext.Session.SetString("2FA_ReturnUrl", returnUrl);
                    
                    _logger.LogInformation("2FA verification required for user {UserId}", user.Id);
                    return RedirectToAction("Verify2fa");
                }
                else
                {
                    // No 2FA enabled - sign in directly
                    _logger.LogInformation("User {UserId} logged in without 2FA enabled", user.Id);

                    // Single active session: issue new session token (kicks out previous session)
                    var previousToken = user.CurrentSessionToken;
                    var isMultipleLogin = !string.IsNullOrEmpty(previousToken);

                    var sessionToken = Guid.NewGuid().ToString();
                    user.CurrentSessionToken = sessionToken;
                    user.SessionIssuedAtUtc = DateTime.UtcNow;
                    await _userManager.UpdateAsync(user);

                    var sessionId = sessionToken;
                    HttpContext.Session.SetString("UserId", user.Id);
                    HttpContext.Session.SetString("SessionId", sessionId);
                    HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("O"));
                    HttpContext.Session.SetString("UserAgent", userAgent);
                    HttpContext.Session.SetString("IpAddress", ipAddress);

                    if (isMultipleLogin)
                    {
                        await LogAuditActivity(user.Id, "Login", $"Multiple login detected. Previous session invalidated.", true, ipAddress, userAgent, sessionId);
                    }
                    else
                    {
                        await LogAuditActivity(user.Id, "Login", "User logged in successfully", true, ipAddress, userAgent, sessionId);
                    }

                    await _signInManager.SignInAsync(user, model.RememberMe);

                    // If password expired, redirect to Change Password instead of home
                    if (IsPasswordExpired(user.PasswordLastChangedAtUtc))
                    {
                        TempData["PasswordExpiredMessage"] = "Your password has expired. Please change it now.";
                        return RedirectToAction(nameof(ChangePassword));
                    }
                    return LocalRedirect(returnUrl);
                }
            }

            if (passwordCheckResult.IsLockedOut)
            {
                // Log locked out attempt
                await LogAuditActivity(user.Id, "Login", "Account locked out due to multiple failed attempts", false, 
                    ipAddress, userAgent, failureReason: "Account locked out");
                
                _logger.LogWarning("User account locked out.");
                HttpContext.Session.Clear();
                CookieClearHelper.ClearSessionCookie(HttpContext);
                ModelState.AddModelError(string.Empty, "Account locked out after 3 failed attempts. Please try again in 1 minute.");
                model.ReturnUrl = returnUrl;
                return View(model);
            }
            else
            {
                // Log failed login attempt
                await LogAuditActivity(user.Id, "Login", "Invalid password attempt", false, 
                    ipAddress, userAgent, failureReason: "Invalid password");
                
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                model.ReturnUrl = returnUrl;
                return View(model);
            }
        }

        [HttpGet]
        public IActionResult Verify2fa()
        {
            var userId = HttpContext.Session.GetString("2FA_UserId");

            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToAction(nameof(Login));
            }

            var model = new TwoFactorViewModel
            {
                RememberMe = bool.TryParse(HttpContext.Session.GetString("2FA_RememberMe"), out var remember) && remember,
                ReturnUrl = HttpContext.Session.GetString("2FA_ReturnUrl")
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2fa(TwoFactorViewModel model)
        {
            var sessionUserId = HttpContext.Session.GetString("2FA_UserId");

            if (string.IsNullOrEmpty(sessionUserId))
            {
                ModelState.AddModelError(string.Empty, "Your verification session has expired. Please login again.");
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(sessionUserId);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Unable to complete verification. Please login again.");
                return View(model);
            }

            // Verify the authenticator code using Identity's built-in TOTP verification
            var isValidCode = await _userManager.VerifyTwoFactorTokenAsync(
                user, TokenOptions.DefaultAuthenticatorProvider, model.Code?.Trim() ?? string.Empty);

            if (!isValidCode)
            {
                ModelState.AddModelError(string.Empty, "The verification code you entered is invalid. Please try again.");
                await LogAuditActivity(user.Id, "Login", "Invalid 2FA code entered", false,
                    HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                    Request.Headers["User-Agent"].ToString(),
                    failureReason: "Invalid authenticator code");
                return View(model);
            }

            // Clear 2FA session state
            HttpContext.Session.Remove("2FA_UserId");
            HttpContext.Session.Remove("2FA_RememberMe");
            HttpContext.Session.Remove("2FA_ReturnUrl");

            // Single active session: issue new session token (kicks out previous session)
            var previousToken = user.CurrentSessionToken;
            var isMultipleLogin = !string.IsNullOrEmpty(previousToken);

            var sessionToken = Guid.NewGuid().ToString();
            user.CurrentSessionToken = sessionToken;
            user.SessionIssuedAtUtc = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = Request.Headers["User-Agent"].ToString();
            var sessionId = sessionToken;
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("SessionId", sessionId);
            HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("O"));
            HttpContext.Session.SetString("UserAgent", userAgent);
            HttpContext.Session.SetString("IpAddress", ipAddress);

            await _signInManager.SignInAsync(user, model.RememberMe);

            if (isMultipleLogin)
            {
                await LogAuditActivity(user.Id, "Login", "Multiple login detected. Previous session invalidated.", true, ipAddress, userAgent, sessionId);
            }
            else
            {
                await LogAuditActivity(user.Id, "Login", "User logged in successfully (2FA)", true, ipAddress, userAgent, sessionId);
            }

            _logger.LogInformation("User logged in with 2FA. Session ID: {SessionId}", sessionId);

            // If password expired, redirect to Change Password instead of home
            if (IsPasswordExpired(user.PasswordLastChangedAtUtc))
            {
                TempData["PasswordExpiredMessage"] = "Your password has expired. Please change it now.";
                return RedirectToAction(nameof(ChangePassword));
            }
            var returnUrl = model.ReturnUrl ?? Url.Content("~/");
            return LocalRedirect(returnUrl);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var sessionId = HttpContext.Session.GetString("SessionId");
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = HttpContext.Session.GetString("UserAgent") ?? Request.Headers["User-Agent"].ToString();

            // Log logout activity before clearing session
            if (!string.IsNullOrEmpty(userId))
            {
                await LogAuditActivity(userId, "Logout", "User logged out successfully", true, 
                    ipAddress, userAgent, sessionId);
            }

            // Invalidate session token in DB (single active session)
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.CurrentSessionToken = null;
                    user.SessionIssuedAtUtc = null;
                    await _userManager.UpdateAsync(user);
                }
            }

            HttpContext.Session.Clear();
            CookieClearHelper.ClearSessionCookie(HttpContext);
            await _signInManager.SignOutAsync();
            CookieClearHelper.ClearAuthCookie(HttpContext);

            _logger.LogInformation("User logged out. Session ID: {SessionId}", sessionId);

            // Redirect to login page after safe logout
            return RedirectToAction("Login", "Account");
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            Response.StatusCode = 403;
            return View();
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Enable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login));
            }

            var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (isTwoFactorEnabled)
            {
                TempData["StatusMessage"] = "Two-factor authentication is already enabled for your account.";
                return RedirectToAction("Index", "Home");
            }

            // Generate authenticator key and QR code URI
            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(authenticatorKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var email = await _userManager.GetEmailAsync(user);
            var issuer = "Ace Job Agency"; // Your app name
            var authenticatorUri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email!)}?secret={authenticatorKey}&issuer={Uri.EscapeDataString(issuer)}";
            
            // Generate QR code URL using a free QR code service
            var qrCodeUrl = $"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={Uri.EscapeDataString(authenticatorUri)}";

            ViewBag.AuthenticatorKey = authenticatorKey;
            ViewBag.QrCodeUrl = qrCodeUrl;
            ViewBag.ManualEntryKey = FormatKeyForDisplay(authenticatorKey);

            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Enable2FA(string code)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login));
            }

            if (string.IsNullOrWhiteSpace(code))
            {
                ModelState.AddModelError(string.Empty, "Verification code is required.");
                return await Enable2FA();
            }

            // Verify the code
            var isValidCode = await _userManager.VerifyTwoFactorTokenAsync(
                user, TokenOptions.DefaultAuthenticatorProvider, code.Trim());

            if (!isValidCode)
            {
                ModelState.AddModelError(string.Empty, "Invalid verification code. Please try again.");
                return await Enable2FA();
            }

            // Enable 2FA for the user
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            
            await LogAuditActivity(user.Id, "Enable2FA", "Two-factor authentication enabled successfully", true,
                HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Request.Headers["User-Agent"].ToString());

            TempData["StatusMessage"] = "Two-factor authentication has been enabled successfully. You will be required to enter a code from your authenticator app when logging in.";
            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login));
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);

            await LogAuditActivity(user.Id, "Disable2FA", "Two-factor authentication disabled", true,
                HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Request.Headers["User-Agent"].ToString());

            TempData["StatusMessage"] = "Two-factor authentication has been disabled for your account.";
            return RedirectToAction("Index", "Home");
        }

        private string FormatKeyForDisplay(string key)
        {
            // Format the key in groups of 4 characters for easier manual entry
            return string.Join(" ", Enumerable.Range(0, key.Length / 4)
                .Select(i => key.Substring(i * 4, 4)));
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null && IsPasswordTooYoung(user.PasswordLastChangedAtUtc))
            {
                TempData["PasswordChangeBlockedMessage"] = $"You recently changed your password. Please wait at least {(int)PasswordMinimumAge.TotalMinutes} minute(s) before changing it again.";
                return RedirectToAction("Index", "Home");
            }
            return View(new ChangePasswordViewModel());
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Enforce minimum password age (cannot change too frequently)
            if (IsPasswordTooYoung(user.PasswordLastChangedAtUtc))
            {
                TempData["PasswordChangeBlockedMessage"] = $"You recently changed your password. Please wait at least {(int)PasswordMinimumAge.TotalMinutes} minute(s) before changing it again.";
                return RedirectToAction("Index", "Home");
            }

            // Enforce password history (no reuse of last N passwords)
            if (await IsPasswordReusedAsync(user, model.NewPassword))
            {
                ModelState.AddModelError(string.Empty,
                    $"You cannot reuse your last {PasswordHistoryDepth} password(s). Please choose a new password.");
                return View(model);
            }

            // Perform the password change
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            await UpdatePasswordAgeAndHistoryAsync(user);

            TempData["StatusMessage"] = "Your password has been changed successfully.";
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View(new ForgotPasswordViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Do not reveal that the user does not exist
                return View("ForgotPasswordConfirmation");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action(
                nameof(ResetPassword),
                "Account",
                new { token, email = user.Email },
                protocol: Request.Scheme)!;

            await _emailSender.SendEmailAsync(
                user.Email!,
                "Reset your Ace Job Agency password",
                $"Please reset your password by clicking <a href=\"{callbackUrl}\">this secure link</a>.");

            return View("ForgotPasswordConfirmation");
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                return RedirectToAction(nameof(Login));
            }

            var model = new ResetPasswordViewModel
            {
                Token = token,
                Email = email
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Do not reveal that the user does not exist
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }

            // Enforce password history and age for reset as well
            if (await IsPasswordReusedAsync(user, model.Password))
            {
                ModelState.AddModelError(string.Empty,
                    $"You cannot reuse your last {PasswordHistoryDepth} password(s). Please choose a new password.");
                return View(model);
            }

            var resetResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            if (!resetResult.Succeeded)
            {
                foreach (var error in resetResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            await UpdatePasswordAgeAndHistoryAsync(user);

            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

    // Server-side password strength validation method
    private void ValidatePasswordStrength(string password, string propertyName)
    {
        if (string.IsNullOrEmpty(password))
        {
            ModelState.AddModelError(propertyName, "Password is required.");
            return;
        }

        if (password.Length < 12)
        {
            ModelState.AddModelError(propertyName, "Password must be at least 12 characters long.");
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(password, @"[a-z]"))
        {
            ModelState.AddModelError(propertyName, "Password must contain at least one lowercase letter.");
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(password, @"[A-Z]"))
        {
            ModelState.AddModelError(propertyName, "Password must contain at least one uppercase letter.");
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(password, @"[0-9]"))
        {
            ModelState.AddModelError(propertyName, "Password must contain at least one number.");
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(password, @"[^a-zA-Z0-9]"))
        {
            ModelState.AddModelError(propertyName, "Password must contain at least one special character.");
        }
    }

    private bool IsPasswordTooYoung(DateTime? lastChangedUtc)
    {
        if (!lastChangedUtc.HasValue)
        {
            return false;
        }

        return DateTime.UtcNow - lastChangedUtc.Value < PasswordMinimumAge;
    }

    private bool IsPasswordExpired(DateTime? lastChangedUtc)
    {
        if (!lastChangedUtc.HasValue)
        {
            return false;
        }

        return DateTime.UtcNow - lastChangedUtc.Value > PasswordMaximumAge;
    }

    private async Task<bool> IsPasswordReusedAsync(ApplicationUser user, string newPassword)
    {
        var recentHistory = await _context.PasswordHistories
            .Where(ph => ph.UserId == user.Id)
            .OrderByDescending(ph => ph.ChangedAtUtc)
            .Take(PasswordHistoryDepth)
            .ToListAsync();

        foreach (var history in recentHistory)
        {
            var verification = _userManager.PasswordHasher.VerifyHashedPassword(
                user, history.PasswordHash, newPassword);

            if (verification == PasswordVerificationResult.Success)
            {
                return true;
            }
        }

        return false;
    }

    private async Task SavePasswordHistoryAsync(ApplicationUser user)
    {
        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            return;
        }

        var history = new PasswordHistory
        {
            UserId = user.Id,
            PasswordHash = user.PasswordHash,
            ChangedAtUtc = DateTime.UtcNow
        };

        _context.PasswordHistories.Add(history);
        await _context.SaveChangesAsync();
    }

    private async Task UpdatePasswordAgeAndHistoryAsync(ApplicationUser user)
    {
        user.PasswordLastChangedAtUtc = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await SavePasswordHistoryAsync(user);

        // Keep only the latest N password history entries
        var histories = await _context.PasswordHistories
            .Where(ph => ph.UserId == user.Id)
            .OrderByDescending(ph => ph.ChangedAtUtc)
            .ToListAsync();

        var toRemove = histories.Skip(PasswordHistoryDepth).ToList();
        if (toRemove.Count > 0)
        {
            _context.PasswordHistories.RemoveRange(toRemove);
            await _context.SaveChangesAsync();
        }
    }

    // Audit logging helper method
    private async Task LogAuditActivity(string userId, string action, string description, bool isSuccess,
        string? ipAddress = null, string? userAgent = null, string? sessionId = null, string? failureReason = null)
    {
        try
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                Description = description,
                IpAddress = ipAddress ?? HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                UserAgent = userAgent ?? Request.Headers["User-Agent"].ToString(),
                SessionId = sessionId ?? HttpContext.Session.GetString("SessionId"),
                Timestamp = DateTime.UtcNow,
                IsSuccess = isSuccess,
                FailureReason = failureReason
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log audit activity for user {UserId}, action {Action}", userId, action);
        }
    }
}
