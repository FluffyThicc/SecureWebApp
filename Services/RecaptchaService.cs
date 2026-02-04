using System.Text.Json;

namespace SecureWebApp.Services;

public class RecaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<RecaptchaService> _logger;

    public RecaptchaService(HttpClient httpClient, IConfiguration configuration, ILogger<RecaptchaService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<bool> VerifyTokenAsync(string token, string? remoteIpAddress = null)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            _logger.LogWarning("reCAPTCHA token is empty");
            return false;
        }

        // Try environment variable first, then fall back to configuration
        var secretKey = Environment.GetEnvironmentVariable("RECAPTCHA_SECRET_KEY") 
            ?? _configuration["Recaptcha:SecretKey"];
            
        if (string.IsNullOrWhiteSpace(secretKey))
        {
            _logger.LogError("reCAPTCHA Secret Key is not configured. Please set RECAPTCHA_SECRET_KEY environment variable or configure in appsettings.json");
            return false;
        }

        try
        {
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("secret", secretKey),
                new KeyValuePair<string, string>("response", token),
                new KeyValuePair<string, string>("remoteip", remoteIpAddress ?? "")
            });

            var response = await _httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<RecaptchaVerificationResult>(responseContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (result == null)
            {
                _logger.LogWarning("Failed to deserialize reCAPTCHA response");
                return false;
            }

            // Log the score for monitoring (v3 returns a score between 0.0 and 1.0)
            if (result.Score.HasValue)
            {
                _logger.LogInformation("reCAPTCHA verification - Success: {Success}, Score: {Score}", result.Success, result.Score.Value);
            }
            else
            {
                _logger.LogInformation("reCAPTCHA verification - Success: {Success}", result.Success);
            }

            // For reCAPTCHA v3, we check both success and score threshold (typically 0.5 or higher)
            // Try environment variable first, then fall back to configuration
            var scoreThresholdEnv = Environment.GetEnvironmentVariable("RECAPTCHA_SCORE_THRESHOLD");
            var scoreThreshold = !string.IsNullOrWhiteSpace(scoreThresholdEnv) && double.TryParse(scoreThresholdEnv, out var threshold)
                ? threshold
                : _configuration.GetValue<double>("Recaptcha:ScoreThreshold", 0.5);
            
            if (result.Success && result.Score.HasValue)
            {
                // Score of 1.0 is very likely a human, 0.0 is very likely a bot
                // Typical threshold is 0.5, but can be adjusted based on needs
                return result.Score.Value >= scoreThreshold;
            }

            return result.Success;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying reCAPTCHA token");
            return false;
        }
    }

    public string GetSiteKey()
    {
        // Try environment variable first, then fall back to configuration
        return Environment.GetEnvironmentVariable("RECAPTCHA_SITE_KEY") 
            ?? _configuration["Recaptcha:SiteKey"] 
            ?? string.Empty;
    }
}

public class RecaptchaVerificationResult
{
    public bool Success { get; set; }
    public double? Score { get; set; }
    public string? Action { get; set; }
    public string? ChallengeTs { get; set; }
    public string? Hostname { get; set; }
    public string[]? ErrorCodes { get; set; }
}

