# Authorization Middleware Integration Guide

This guide demonstrates how to integrate the Shift Authorization Infrastructure middleware and service extensions into your ASP.NET Core services.

## Installation

Install the NuGet package:

```bash
dotnet add package Shift.Authorization.Infrastructure
```

## Basic Setup

### 1. Configure Services (Program.cs or Startup.cs)

```csharp
using Shift.Authorization.Infrastructure.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add Shift Authorization with basic configuration
builder.Services.AddShiftAuthorization(options =>
{
    options.JwtValidationKey = builder.Configuration["Jwt:SecretKey"];
    options.JwtIssuer = builder.Configuration["Jwt:Issuer"];
    options.JwtAudience = builder.Configuration["Jwt:Audience"];
    options.EnableOperationalContext = true;
});

// Or load from configuration
builder.Services.AddShiftAuthorization(builder.Configuration.GetSection("Authorization"));

var app = builder.Build();

// Add authorization middleware to the pipeline
app.UseShiftAuthorization();

// Your other middleware...
app.UseRouting();
app.MapControllers();

app.Run();
```

### 2. Configuration Options

Add to your `appsettings.json`:

```json
{
  "Authorization": {
    "EnableOperationalContext": true,
    "JwtValidationKey": "your-secret-key-at-least-256-bits",
    "JwtIssuer": "your-issuer",
    "JwtAudience": "your-audience",
    "ValidateIssuer": true,
    "ValidateAudience": true,
    "ValidateLifetime": true,
    "RequireHttpsMetadata": true,
    "ClockSkew": "00:05:00",
    "IncludeErrorDetails": false,
    "EnableAsyncOperationalContextResolution": false,
    "PermissionMappings": [
      {
        "Permission": "custom:admin",
        "Scope": "Platform",
        "Description": "Custom admin permission"
      }
    ]
  }
}
```

## Using Authorization Context

### In Controllers

```csharp
[ApiController]
[Route("api/[controller]")]
public class TenantsController : ControllerBase
{
    private readonly IAuthorizationContext _authContext;

    public TenantsController(IAuthorizationContext authContext)
    {
        _authContext = authContext;
    }

    [HttpGet("{tenantId}")]
    public IActionResult GetTenant(string tenantId)
    {
        // Check if user can access the tenant
        if (!_authContext.CanAccessTenant(tenantId))
        {
            return Forbid();
        }

        // Check specific permission with scope
        if (!_authContext.HasPermission("tenant:read", AuthorizationScope.Tenant))
        {
            return Forbid();
        }

        // Your logic here
        return Ok(new {
            tenantId,
            currentUser = _authContext.UserId,
            userType = _authContext.UserType
        });
    }
}
```

### In Services

```csharp
public class TenantService
{
    private readonly IAuthorizationContext _authContext;

    public TenantService(IAuthorizationContext authContext)
    {
        _authContext = authContext;
    }

    public async Task<TenantDto?> GetTenantAsync(string tenantId)
    {
        // Authorization check
        if (!_authContext.CanAccessTenant(tenantId))
        {
            throw new UnauthorizedAccessException($"User {_authContext.UserId} cannot access tenant {tenantId}");
        }

        // Service logic
        // ...
    }
}
```

## Operational Context Headers

SuperAdmin and TenantAdmin users can operate on behalf of different tenants/clients using special headers:

### SuperAdmin Operations

```http
GET /api/tenants/tenant-123/clients
Authorization: Bearer {superadmin-jwt-token}
X-Operation-Tenant-Id: tenant-123
X-Operation-Client-Id: client-456
```

### TenantAdmin Operations

```http
GET /api/clients/client-789/documents
Authorization: Bearer {tenantadmin-jwt-token}
X-Operation-Client-Id: client-789
```

**Note:** TenantAdmin users can only set `X-Operation-Client-Id` for clients within their own tenant.

## Advanced Configuration

### Custom Permission Mappings

```csharp
builder.Services.AddShiftAuthorization()
    .AddPermissionScopeMapping("reports:generate", AuthorizationScope.Platform, "Generate platform reports")
    .AddPermissionScopeMapping("users:manage", AuthorizationScope.Tenant, "Manage tenant users")
    .AddPermissionScopeMapping("documents:upload", AuthorizationScope.Own, "Upload own documents");
```

### JWT Configuration

```csharp
builder.Services.AddShiftAuthorization()
    .ConfigureJwtValidation(
        validationKey: "your-secret-key",
        issuer: "https://identity.yourservice.com",
        audience: "api.yourservice.com"
    );
```

### Async Operational Context Resolution

For scenarios requiring database lookups:

```csharp
public class CustomOperationalContextResolver : IOperationalContextResolverAsync
{
    private readonly IDbContext _db;

    public async Task<OperationalContext> ResolveContextAsync(
        HttpContext httpContext,
        IAuthorizationContext authContext)
    {
        // Custom async resolution logic
        // ...
    }

    public async Task<bool> ValidateOperationalAccessAsync(
        string? targetTenantId,
        string? targetClientId,
        IAuthorizationContext authContext)
    {
        // Validate against database
        // ...
    }
}

// Register custom resolver
builder.Services.AddScoped<IOperationalContextResolverAsync, CustomOperationalContextResolver>();
builder.Services.AddShiftAuthorization(options =>
{
    options.EnableAsyncOperationalContextResolution = true;
});
```

## Error Handling

The middleware returns appropriate HTTP status codes:

- **401 Unauthorized**: Invalid or missing JWT token
- **403 Forbidden**: Valid token but insufficient permissions or unauthorized operational context
- **500 Internal Server Error**: Unexpected authorization processing error

### Error Response Format

```json
{
  "error": "forbidden",
  "message": "Authorization failed",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

Enable detailed errors for development:

```csharp
builder.Services.AddShiftAuthorization(options =>
{
    options.IncludeErrorDetails = builder.Environment.IsDevelopment();
});
```

## Testing

### Unit Testing with Mock Context

```csharp
[Fact]
public void TestServiceWithMockAuth()
{
    // Arrange
    var mockContext = new AuthorizationContext(
        userId: "test-user",
        tenantId: "test-tenant",
        clientId: "test-client",
        userType: UserType.TenantAdmin,
        permissions: new List<string> { "read", "write" }
    );

    var service = new YourService(mockContext);

    // Act & Assert
    // ...
}
```

### Integration Testing

```csharp
public class IntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    [Fact]
    public async Task GetEndpoint_WithValidToken_ReturnsSuccess()
    {
        // Arrange
        var client = _factory.CreateClient();
        var token = GenerateTestJwt();

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await client.GetAsync("/api/test");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
```

## Migration from Direct JWT Handling

If you're currently handling JWT validation manually:

### Before
```csharp
[Authorize]
public class MyController : ControllerBase
{
    public IActionResult Get()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var tenantId = User.FindFirst("tenant_id")?.Value;
        // Manual permission checking...
    }
}
```

### After
```csharp
public class MyController : ControllerBase
{
    private readonly IAuthorizationContext _authContext;

    public MyController(IAuthorizationContext authContext)
    {
        _authContext = authContext;
    }

    public IActionResult Get()
    {
        // Direct access to strongly-typed context
        var userId = _authContext.UserId;
        var tenantId = _authContext.TenantId;

        // Built-in permission checking
        if (!_authContext.HasPermission("resource:read", AuthorizationScope.Tenant))
        {
            return Forbid();
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **InvalidOperationException: Authorization context is not available**
   - Ensure `UseShiftAuthorization()` is called in the pipeline
   - Verify it's placed before any middleware that needs authorization

2. **401 Unauthorized with valid token**
   - Check JWT validation settings match your identity provider
   - Verify token expiration and clock skew settings

3. **Operational context not working**
   - Ensure `EnableOperationalContext` is true
   - Verify user type allows operational context (SuperAdmin/TenantAdmin only)

### Logging

Enable debug logging to troubleshoot:

```json
{
  "Logging": {
    "LogLevel": {
      "Shift.Authorization.Infrastructure": "Debug"
    }
  }
}
```

## Best Practices

1. **Always validate authorization at the service layer**, not just controllers
2. **Use appropriate scopes** for permissions based on resource ownership
3. **Configure clock skew** appropriately for distributed systems
4. **Enable operational context** only if needed for admin operations
5. **Use async resolvers** for complex validation requiring database access
6. **Keep JWT validation keys secure** and rotate regularly
7. **Monitor authorization failures** through logging and telemetry