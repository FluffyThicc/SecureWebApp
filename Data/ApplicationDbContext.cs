using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Models;

namespace SecureWebApp.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{

    // Database constructor receives database configuration like connection string
    // in appsettings.json file.
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Audit Log table for tracking user activities
    public DbSet<AuditLog> AuditLogs { get; set; }

    // Password history table for enforcing password reuse policies
    public DbSet<PasswordHistory> PasswordHistories { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure AuditLog table
        builder.Entity<AuditLog>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.Action);
        });

        // Configure PasswordHistory table
        builder.Entity<PasswordHistory>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.ChangedAtUtc);
        });
    }
}

