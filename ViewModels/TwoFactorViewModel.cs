using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class TwoFactorViewModel
{
    [Required(ErrorMessage = "Verification code is required")]
    [Display(Name = "Verification Code")]
    public string Code { get; set; } = string.Empty;

    public bool RememberMe { get; set; }

    public string? ReturnUrl { get; set; }
}


