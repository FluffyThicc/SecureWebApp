using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class ChangePasswordViewModel
{
    [Required(ErrorMessage = "Current password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "Current Password")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "New password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "New Password")]
    [PasswordStrength(ErrorMessage = "Password must be at least 12 characters with uppercase, lowercase, number, and special character.")]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirm new password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm New Password")]
    [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
    public string ConfirmNewPassword { get; set; } = string.Empty;
}


