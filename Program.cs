using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var jwtKey = "EduCore-Admin-Secret-Key-2024!@#$%";

var connStr = Environment.GetEnvironmentVariable("CONNECTION_STRING") ?? "Host=localhost;Database=admin_panel;Username=admin_panel_user;Password=AdminPanel2024";
builder.Services.AddDbContext<AdminDb>(opt => opt.UseNpgsql(connStr));
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

// JWT Authentication
builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
    };
});
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseDefaultFiles();
app.UseStaticFiles();

// Ensure DB + seed super admin
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AdminDb>();
    db.Database.EnsureCreated();
    if (!db.SuperAdmins.Any())
    {
        db.SuperAdmins.Add(new SuperAdmin
        {
            Name = "Super Admin",
            Email = "admin@educore.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin123"),
        });
        db.SaveChanges();
    }
}

// Helper to extract claims
static ClaimsPrincipal? ValidateToken(string? authHeader, string jwtKey)
{
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ")) return null;
    var token = authHeader["Bearer ".Length..];
    try
    {
        return new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        }, out _);
    }
    catch { return null; }
}

// === Auth ===
app.MapPost("/api/auth/login", async (LoginRequest req, AdminDb db) =>
{
    var admin = await db.SuperAdmins.FirstOrDefaultAsync(a => a.Email == req.Email);
    if (admin == null || !BCrypt.Net.BCrypt.Verify(req.Password, admin.PasswordHash))
        return Results.Unauthorized();

    var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
        claims: new[] {
            new Claim(ClaimTypes.NameIdentifier, admin.Id.ToString()),
            new Claim(ClaimTypes.Name, admin.Name),
            new Claim(ClaimTypes.Role, "super_admin"),
        },
        expires: DateTime.UtcNow.AddDays(30),
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            SecurityAlgorithms.HmacSha256)
    ));
    return Results.Ok(new LoginResponse(token, admin.Name));
});

// === Organizations (protegido) ===
app.MapGet("/api/organizations", async (HttpContext ctx, AdminDb db) =>
{
    var user = ValidateToken(ctx.Request.Headers["Authorization"], jwtKey);
    if (user == null) return Results.Unauthorized();
    if (!user.IsInRole("super_admin")) return Results.Forbid();
    return Results.Ok(await db.Organizations.OrderByDescending(o => o.CreatedAt)
        .Select(o => new OrgResponse(o.Id, o.Name, o.Slug, o.Document, o.Status, o.CreatedAt))
        .ToListAsync());
});

app.MapPost("/api/organizations", async (HttpContext ctx, CreateOrgRequest req, AdminDb db) =>
{
    var user = ValidateToken(ctx.Request.Headers["Authorization"], jwtKey);
    if (user == null) return Results.Unauthorized();
    if (!user.IsInRole("super_admin")) return Results.Forbid();

    var slug = req.Slug.ToLower().Replace(" ", "-");
    if (await db.Organizations.AnyAsync(o => o.Slug == slug))
        return Results.BadRequest(new { message = "Slug já existe" });
    if (await db.AdminUsers.AnyAsync(u => u.Email == req.AdminEmail))
        return Results.BadRequest(new { message = "Email admin já usado" });

    var org = new Organization { Name = req.Name, Slug = slug, Document = req.Document };
    db.Organizations.Add(org);
    await db.SaveChangesAsync();

    var adminUser = new AdminUser
    {
        OrganizationId = org.Id,
        Name = req.AdminName,
        Email = req.AdminEmail,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.AdminPassword),
    };
    db.AdminUsers.Add(adminUser);
    await db.SaveChangesAsync();

    return Results.Created($"/api/organizations/{org.Id}", new OrgResponse(org.Id, org.Name, org.Slug, org.Document, org.Status, org.CreatedAt));
});

app.MapMethods("/api/organizations/{id}/status", new[] { "PATCH" }, async (HttpContext ctx, Guid id, string status, AdminDb db) =>
{
    var user = ValidateToken(ctx.Request.Headers["Authorization"], jwtKey);
    if (user == null) return Results.Unauthorized();
    if (!user.IsInRole("super_admin")) return Results.Forbid();

    var org = await db.Organizations.FindAsync(id);
    if (org == null) return Results.NotFound();
    org.Status = status;
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "Status atualizado" });
});

app.MapGet("/api/organizations/{id}/admins", async (HttpContext ctx, Guid id, AdminDb db) =>
{
    var user = ValidateToken(ctx.Request.Headers["Authorization"], jwtKey);
    if (user == null) return Results.Unauthorized();
    if (!user.IsInRole("super_admin")) return Results.Forbid();

    return Results.Ok(await db.AdminUsers.Where(u => u.OrganizationId == id)
        .Select(u => new AdminUserResponse(u.Id, u.Name, u.Email, u.Active))
        .ToListAsync());
});

app.MapGet("/api/stats", async (HttpContext ctx, AdminDb db) =>
{
    var user = ValidateToken(ctx.Request.Headers["Authorization"], jwtKey);
    if (user == null) return Results.Unauthorized();
    if (!user.IsInRole("super_admin")) return Results.Forbid();

    var totalOrgs = await db.Organizations.CountAsync();
    var activeOrgs = await db.Organizations.CountAsync(o => o.Status == "active");
    return Results.Ok(new { totalOrgs, activeOrgs });
});

app.Run();
