using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SecureWebApp.Services;

/// <summary>
/// Email sender implementation for password reset links and two-factor authentication codes.
/// Uses SMTP when configured; otherwise logs the email content (for development without SMTP).
/// </summary>
public interface IEmailSender
{
    Task SendEmailAsync(string toEmail, string subject, string htmlMessage);
}

public class EmailSender : IEmailSender
{
    private readonly ILogger<EmailSender> _logger;
    private readonly IConfiguration _configuration;

    public EmailSender(ILogger<EmailSender> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public async Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
    {
        var host = _configuration["Smtp:Host"];
        if (string.IsNullOrWhiteSpace(host))
        {
            _logger.LogInformation("SMTP not configured. Would send email to {Email} with subject '{Subject}'. Body: {Body}",
                toEmail, subject, htmlMessage);
            return;
        }

        var port = _configuration.GetValue<int>("Smtp:Port", 587);
        var userName = _configuration["Smtp:UserName"];
        var password = _configuration["Smtp:Password"];
        var fromEmail = _configuration["Smtp:FromEmail"] ?? userName ?? "noreply@example.com";
        var enableSsl = _configuration.GetValue<bool>("Smtp:EnableSsl", true);

        using var client = new SmtpClient(host, port)
        {
            EnableSsl = enableSsl,
            Credentials = !string.IsNullOrWhiteSpace(userName) && !string.IsNullOrWhiteSpace(password)
                ? new NetworkCredential(userName, password)
                : null
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(fromEmail, "Ace Job Agency"),
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true
        };
        mailMessage.To.Add(toEmail);

        try
        {
            await client.SendMailAsync(mailMessage);
            _logger.LogInformation("Email sent successfully to {Email} with subject '{Subject}'.", toEmail, subject);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {Email} with subject '{Subject}'.", toEmail, subject);
            throw;
        }
    }
}
