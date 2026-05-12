using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

// === Models ===

public class SuperAdmin
{
    [Key] public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
}

public class Organization
{
    [Key] public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Slug { get; set; } = "";
    public string? Document { get; set; }
    public string Status { get; set; } = "active";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class AdminUser
{
    [Key] public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OrganizationId { get; set; }
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool Active { get; set; } = true;

    [ForeignKey("OrganizationId")] public Organization? Organization { get; set; }
}

// === DB ===

public class AdminDb : DbContext
{
    public AdminDb(DbContextOptions<AdminDb> options) : base(options) { }
    public DbSet<SuperAdmin> SuperAdmins => Set<SuperAdmin>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<AdminUser> AdminUsers => Set<AdminUser>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SuperAdmin>(e => { e.HasIndex(a => a.Email).IsUnique(); });
        modelBuilder.Entity<Organization>(e => { e.HasIndex(o => o.Slug).IsUnique(); });
        modelBuilder.Entity<AdminUser>(e => { e.HasIndex(u => u.Email).IsUnique(); });
    }
}

// === DTOs ===

public record LoginRequest(string Email, string Password);
public record LoginResponse(string Token, string Name);
public record CreateOrgRequest(string Name, string Slug, string? Document, string AdminName, string AdminEmail, string AdminPassword);
public record OrgResponse(Guid Id, string Name, string Slug, string? Document, string Status, DateTime CreatedAt);
public record AdminUserResponse(Guid Id, string Name, string Email, bool Active);
