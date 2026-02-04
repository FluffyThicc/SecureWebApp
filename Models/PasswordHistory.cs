using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

/// <summary>
/// Tracks historical password hashes for each user so that we can prevent
/// recent password reuse (e.g. last 2 passwords).
/// </summary>
public class PasswordHistory
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    [Required]
    public DateTime ChangedAtUtc { get; set; }
}


