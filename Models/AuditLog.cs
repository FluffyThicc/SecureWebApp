using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class AuditLog
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    [StringLength(100)]
    public string Action { get; set; } = string.Empty; // Login, Logout, Register, etc.

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(50)]
    public string? IpAddress { get; set; }

    [StringLength(500)]
    public string? UserAgent { get; set; }

    [StringLength(100)]
    public string? SessionId { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public bool IsSuccess { get; set; }

    [StringLength(500)]
    public string? FailureReason { get; set; }
}





