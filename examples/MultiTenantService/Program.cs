using Microsoft.AspNetCore.Mvc;
using Shift.Authorization.Infrastructure;
using Shift.Authorization.Infrastructure.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register mock services
builder.Services.AddScoped<ITenantService, TenantService>();
builder.Services.AddScoped<IClientTenantValidator, ClientTenantValidator>();

// Configure Shift Authorization with operational context enabled
builder.Services.AddShiftAuthorization(options =>
{
    // JWT Configuration
    options.JwtValidationKey = "ThisIsAVerySecretKeyForMultiTenantExampleWithAtLeast256Bits!";
    options.JwtIssuer = "shift-multitenant-issuer";
    options.JwtAudience = "shift-multitenant-audience";

    // Security settings
    options.ValidateIssuer = true;
    options.ValidateAudience = true;
    options.ValidateLifetime = true;

    // Enable operational context for cross-tenant operations
    options.EnableOperationalContext = true;
    options.EnableAsyncOperationalContextResolution = true;

    // Enable detailed error information for development
    options.IncludeErrorDetails = builder.Environment.IsDevelopment();

    // Configure custom permission mappings
})
.AddPermissionScopeMapping("reports:generate", AuthorizationScope.Tenant, "Generate reports for tenant")
.AddPermissionScopeMapping("audit:view", AuthorizationScope.Platform, "View audit logs")
.ConfigureJwtValidation(
    validationKey: "ThisIsAVerySecretKeyForMultiTenantExampleWithAtLeast256Bits!",
    issuer: "shift-multitenant-issuer",
    audience: "shift-multitenant-audience");

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Use Shift Authorization middleware
app.UseShiftAuthorization();

// Tenant management endpoints
app.MapGet("/tenants", async (ITenantService tenantService, IAuthorizationContext context) =>
{
    if (!context.HasPermission("tenant:read", AuthorizationScope.Platform))
    {
        return Results.Forbid();
    }

    var tenants = await tenantService.GetAllTenantsAsync();
    return Results.Ok(tenants);
})
.WithName("GetAllTenants")
.WithOpenApi();

app.MapGet("/tenants/{tenantId}", async (string tenantId, ITenantService tenantService, IAuthorizationContext context) =>
{
    if (!context.CanAccessTenant(tenantId) ||
        !context.HasPermission("tenant:read", AuthorizationScope.Tenant))
    {
        return Results.Forbid();
    }

    var tenant = await tenantService.GetTenantAsync(tenantId);
    return tenant != null ? Results.Ok(tenant) : Results.NotFound();
})
.WithName("GetTenant")
.WithOpenApi();

// Cross-tenant operations (SuperAdmin only, uses operational context)
app.MapPost("/admin/cross-tenant/bulk-update", async (
    [FromBody] CrossTenantBulkRequest request,
    ITenantService tenantService,
    IAuthorizationContext context) =>
{
    // Only SuperAdmin can perform cross-tenant operations
    if (context.UserType != UserType.SuperAdmin ||
        !context.HasPermission("admin:write", AuthorizationScope.Platform))
    {
        return Results.Forbid();
    }

    var results = new List<BulkUpdateResult>();

    foreach (var tenantId in request.TenantIds)
    {
        try
        {
            await tenantService.UpdateTenantSettingsAsync(tenantId, request.Settings);
            results.Add(new BulkUpdateResult { TenantId = tenantId, Success = true });
        }
        catch (Exception ex)
        {
            results.Add(new BulkUpdateResult
            {
                TenantId = tenantId,
                Success = false,
                Error = ex.Message
            });
        }
    }

    return Results.Ok(new { Results = results, TotalProcessed = results.Count });
})
.WithName("CrossTenantBulkUpdate")
.WithOpenApi();

// Operational context example - SuperAdmin operating as a specific tenant
app.MapGet("/admin/impersonate/tenant/{tenantId}/clients", async (
    string tenantId,
    ITenantService tenantService,
    IAuthorizationContext context,
    HttpContext httpContext) =>
{
    // This endpoint demonstrates operational context headers
    // SuperAdmin can set X-Operational-Tenant-Id header to operate as that tenant

    if (context.UserType != UserType.SuperAdmin)
    {
        return Results.Forbid();
    }

    // The operational context middleware will have resolved the effective tenant
    var effectiveTenantId = context.TenantId ?? tenantId;

    var clients = await tenantService.GetTenantClientsAsync(effectiveTenantId);
    return Results.Ok(new
    {
        OriginalUserType = "SuperAdmin",
        EffectiveTenantId = effectiveTenantId,
        OperatingAs = context.TenantId != null ? "Tenant Context" : "Platform Context",
        Clients = clients
    });
})
.WithName("ImpersonateTenant")
.WithOpenApi();

// Client management within tenant
app.MapGet("/tenants/{tenantId}/clients", async (
    string tenantId,
    ITenantService tenantService,
    IAuthorizationContext context) =>
{
    if (!context.CanAccessTenant(tenantId) ||
        !context.HasPermission("client:read", AuthorizationScope.Tenant))
    {
        return Results.Forbid();
    }

    var clients = await tenantService.GetTenantClientsAsync(tenantId);
    return Results.Ok(clients);
})
.WithName("GetTenantClients")
.WithOpenApi();

// Advanced: Tenant-scoped reporting
app.MapPost("/tenants/{tenantId}/reports/generate", async (
    string tenantId,
    [FromBody] ReportRequest request,
    ITenantService tenantService,
    IAuthorizationContext context) =>
{
    // Check access to tenant and permission
    if (!context.CanAccessTenant(tenantId) ||
        !context.HasPermission("reports:generate", AuthorizationScope.Tenant))
    {
        return Results.Forbid();
    }

    var report = await tenantService.GenerateReportAsync(tenantId, request);
    return Results.Ok(report);
})
.WithName("GenerateTenantReport")
.WithOpenApi();

// Health check with authorization info
app.MapGet("/health", (IAuthorizationContext context) => new
{
    Status = "Healthy",
    Timestamp = DateTime.UtcNow,
    User = new
    {
        context.UserId,
        UserType = context.UserType.ToString(),
        context.TenantId,
        context.ClientId,
        PermissionCount = context.Permissions.Count
    }
})
.WithName("HealthCheck")
.WithOpenApi();

app.Run();

// Models
public record CrossTenantBulkRequest(List<string> TenantIds, Dictionary<string, object> Settings);
public record BulkUpdateResult(string TenantId, bool Success, string? Error = null);
public record ReportRequest(string ReportType, Dictionary<string, object> Parameters);
public record TenantInfo(string Id, string Name, bool IsActive, int ClientCount);
public record ClientInfo(string Id, string Name, string TenantId, bool IsActive);
public record ReportResult(string Id, string Type, DateTime GeneratedAt, object Data);

// Services
public interface ITenantService
{
    Task<List<TenantInfo>> GetAllTenantsAsync();
    Task<TenantInfo?> GetTenantAsync(string tenantId);
    Task<List<ClientInfo>> GetTenantClientsAsync(string tenantId);
    Task UpdateTenantSettingsAsync(string tenantId, Dictionary<string, object> settings);
    Task<ReportResult> GenerateReportAsync(string tenantId, ReportRequest request);
}

public class TenantService : ITenantService
{
    // Mock data
    private static readonly List<TenantInfo> MockTenants = new()
    {
        new("tenant-001", "Acme Corp", true, 5),
        new("tenant-002", "Global Inc", true, 12),
        new("tenant-003", "StartupXYZ", true, 3)
    };

    private static readonly List<ClientInfo> MockClients = new()
    {
        new("client-001", "Alice Johnson", "tenant-001", true),
        new("client-002", "Bob Smith", "tenant-001", true),
        new("client-003", "Carol White", "tenant-002", true),
        new("client-004", "David Brown", "tenant-002", false)
    };

    public Task<List<TenantInfo>> GetAllTenantsAsync()
    {
        return Task.FromResult(MockTenants);
    }

    public Task<TenantInfo?> GetTenantAsync(string tenantId)
    {
        var tenant = MockTenants.FirstOrDefault(t => t.Id == tenantId);
        return Task.FromResult(tenant);
    }

    public Task<List<ClientInfo>> GetTenantClientsAsync(string tenantId)
    {
        var clients = MockClients.Where(c => c.TenantId == tenantId).ToList();
        return Task.FromResult(clients);
    }

    public Task UpdateTenantSettingsAsync(string tenantId, Dictionary<string, object> settings)
    {
        // Mock implementation - in real scenario, this would update database
        Console.WriteLine($"Updating settings for tenant {tenantId}: {string.Join(", ", settings.Keys)}");
        return Task.CompletedTask;
    }

    public Task<ReportResult> GenerateReportAsync(string tenantId, ReportRequest request)
    {
        var report = new ReportResult(
            Id: Guid.NewGuid().ToString(),
            Type: request.ReportType,
            GeneratedAt: DateTime.UtcNow,
            Data: new { TenantId = tenantId, Parameters = request.Parameters }
        );

        return Task.FromResult(report);
    }
}

public class ClientTenantValidator : IClientTenantValidator
{
    public bool IsValidClientTenantCombination(string clientId, string tenantId)
    {
        // Mock validation - in real scenario, this would check database
        var validCombinations = new Dictionary<string, string>
        {
            ["client-001"] = "tenant-001",
            ["client-002"] = "tenant-001",
            ["client-003"] = "tenant-002",
            ["client-004"] = "tenant-002"
        };

        return validCombinations.TryGetValue(clientId, out var validTenantId) &&
               validTenantId == tenantId;
    }
}