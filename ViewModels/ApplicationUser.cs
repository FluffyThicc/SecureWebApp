using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class ApplicationUser : IdentityUser
{
    [Required]
    [Display(Name = "First Name")]
    [StringLength(50)]
    public string FirstName { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Last Name")]
    [StringLength(50)]
    public string LastName { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Gender")]
    public string Gender { get; set; } = string.Empty;

    [Required]
    [Display(Name = "NRIC")]
    [StringLength(100)] // Encrypted NRIC will be longer
    public string EncryptedNRIC { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Date of Birth")]
    [DataType(DataType.Date)]
    public DateTime DateOfBirth { get; set; }

    [Display(Name = "Resume File Path")]
    public string? ResumeFilePath { get; set; }

    [Display(Name = "Resume File Name")]
    public string? ResumeFileName { get; set; }

    [Display(Name = "Who Am I")]
    [StringLength(1000)]
    public string? WhoAmI { get; set; }

    /// <summary>
    /// The last time (in UTC) that the user successfully changed their password.
    /// Used to enforce minimum and maximum password age policies.
    /// </summary>
    public DateTime? PasswordLastChangedAtUtc { get; set; }
}

