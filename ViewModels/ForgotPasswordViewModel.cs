using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "Email address is required")]
    [EmailAddress(ErrorMessage = "Invalid email address format")]
    [Display(Name = "Email Address")]
    public string Email { get; set; } = string.Empty;
}


