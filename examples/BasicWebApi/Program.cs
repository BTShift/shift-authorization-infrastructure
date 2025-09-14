using Microsoft.AspNetCore.Mvc;
using Shift.Authorization.Infrastructure;
using Shift.Authorization.Infrastructure.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure Shift Authorization
builder.Services.AddShiftAuthorization(options =>
{
    // JWT Configuration
    options.JwtValidationKey = "ThisIsAVerySecretKeyForExamplePurposesOnlyWithAtLeast256Bits!";
    options.JwtIssuer = "shift-example-issuer";
    options.JwtAudience = "shift-example-audience";

    // Security settings
    options.ValidateIssuer = true;
    options.ValidateAudience = true;
    options.ValidateLifetime = true;

    // Optional: Enable operational context for cross-tenant operations
    options.EnableOperationalContext = false;

    // Optional: Enable detailed error information for development
    options.IncludeErrorDetails = builder.Environment.IsDevelopment();
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Use Shift Authorization middleware
app.UseShiftAuthorization();

// Public endpoint - no authorization required
app.MapGet("/public", () => new { Message = "This is a public endpoint" })
    .WithName("GetPublic")
    .WithOpenApi();

// Protected endpoint - requires authentication
app.MapGet("/profile", (IAuthorizationContext context) => new
{
    UserId = context.UserId,
    UserType = context.UserType.ToString(),
    TenantId = context.TenantId,
    ClientId = context.ClientId,
    Permissions = context.Permissions
})
.WithName("GetProfile")
.WithOpenApi();

// Permission-based endpoint
app.MapGet("/admin/users", (IAuthorizationContext context) =>
{
    // Check if user has admin permission at platform level
    if (!context.HasPermission("admin:read", AuthorizationScope.Platform))
    {
        return Results.Forbid();
    }

    return Results.Ok(new { Users = new[] { "user1", "user2", "user3" } });
})
.WithName("GetUsers")
.WithOpenApi();

// Tenant-specific endpoint
app.MapGet("/tenant/{tenantId}/clients", (string tenantId, IAuthorizationContext context) =>
{
    // Check if user can access this tenant
    if (!context.CanAccessTenant(tenantId))
    {
        return Results.Forbid();
    }

    // Check if user has required permission for tenant operations
    if (!context.HasPermission("tenant:read", AuthorizationScope.Tenant))
    {
        return Results.Forbid();
    }

    return Results.Ok(new { TenantId = tenantId, Clients = new[] { "client1", "client2" } });
})
.WithName("GetTenantClients")
.WithOpenApi();

// Client-specific endpoint
app.MapPost("/client/{clientId}/documents", async (string clientId, [FromBody] DocumentRequest request, IAuthorizationContext context) =>
{
    // Check if user can access this client
    if (!context.CanAccessClient(clientId))
    {
        return Results.Forbid();
    }

    // Check if user has required permission
    if (!context.HasPermission("client:write", AuthorizationScope.Own))
    {
        return Results.Forbid();
    }

    // Simulate document creation
    var document = new
    {
        Id = Guid.NewGuid(),
        ClientId = clientId,
        Title = request.Title,
        Content = request.Content,
        CreatedBy = context.UserId,
        CreatedAt = DateTime.UtcNow
    };

    return Results.Created($"/client/{clientId}/documents/{document.Id}", document);
})
.WithName("CreateDocument")
.WithOpenApi();

// Health check endpoint
app.MapGet("/health", () => new { Status = "Healthy", Timestamp = DateTime.UtcNow })
    .WithName("HealthCheck")
    .WithOpenApi();

app.Run();

// Request models
public record DocumentRequest(string Title, string Content);

// Extension methods for better API organization
public static class AuthorizationEndpoints
{
    public static WebApplication MapAuthorizationExamples(this WebApplication app)
    {
        var group = app.MapGroup("/examples").WithTags("Authorization Examples");

        // Example: Multiple permission check
        group.MapGet("/multi-permission", (IAuthorizationContext context) =>
        {
            var results = new Dictionary<string, bool>
            {
                ["can_read_platform"] = context.HasPermission("platform:read", AuthorizationScope.Platform),
                ["can_read_tenant"] = context.HasPermission("tenant:read", AuthorizationScope.Tenant),
                ["can_write_client"] = context.HasPermission("client:write", AuthorizationScope.Own)
            };

            return Results.Ok(results);
        });

        // Example: Scope-based access control
        group.MapGet("/scope-demo/{scope}", (string scope, IAuthorizationContext context) =>
        {
            var authScope = scope.ToLowerInvariant() switch
            {
                "platform" => AuthorizationScope.Platform,
                "tenant" => AuthorizationScope.Tenant,
                "own" => AuthorizationScope.Own,
                _ => AuthorizationScope.Own
            };

            var hasAccess = context.HasPermission("demo:access", authScope);

            return Results.Ok(new
            {
                RequestedScope = scope,
                UserType = context.UserType.ToString(),
                HasAccess = hasAccess,
                Message = hasAccess ? "Access granted" : "Access denied"
            });
        });

        return app;
    }
}