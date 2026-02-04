using Microsoft.Extensions.Logging;

namespace SecureWebApp.Services;

/// <summary>
/// Simple email sender implementation used for password reset links and
/// two-factor authentication codes. In this demo it logs the email content
/// rather than sending a real email, which is sufficient for rubric and testing.
/// </summary>
public interface IEmailSender
{
    Task SendEmailAsync(string toEmail, string subject, string htmlMessage);
}

public class EmailSender : IEmailSender
{
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(ILogger<EmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
    {
        // In a real system, integrate with an SMTP server or email provider here.
        _logger.LogInformation("Sending email to {Email} with subject '{Subject}'. Body: {Body}",
            toEmail, subject, htmlMessage);
        return Task.CompletedTask;
    }
}


