using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SecureWebApp.Models;

public class PasswordStrengthAttribute : ValidationAttribute
{
    public override bool IsValid(object? value)
    {
        if (value is not string password || string.IsNullOrEmpty(password))
        {
            ErrorMessage = "Password is required.";
            return false;
        }

        if (password.Length < 12)
        {
            ErrorMessage = "Password must be at least 12 characters long.";
            return false;
        }

        if (!Regex.IsMatch(password, @"[a-z]"))
        {
            ErrorMessage = "Password must contain at least one lowercase letter.";
            return false;
        }

        if (!Regex.IsMatch(password, @"[A-Z]"))
        {
            ErrorMessage = "Password must contain at least one uppercase letter.";
            return false;
        }

        if (!Regex.IsMatch(password, @"[0-9]"))
        {
            ErrorMessage = "Password must contain at least one number.";
            return false;
        }

        if (!Regex.IsMatch(password, @"[^a-zA-Z0-9]"))
        {
            ErrorMessage = "Password must contain at least one special character.";
            return false;
        }

        return true;
    }
}

