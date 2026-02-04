using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class ResetPasswordViewModel
{
    [Required]
    public string Token { get; set; } = string.Empty;

    [Required]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "New password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "New Password")]
    [PasswordStrength(ErrorMessage = "Password must be at least 12 characters with uppercase, lowercase, number, and special character.")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirm password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}


