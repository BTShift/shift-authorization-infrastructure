# Operational Context Headers

## Overview

The Operational Context system allows authorized users (SuperAdmin and TenantAdmin) to perform operations on behalf of different tenants or clients using special HTTP headers. This is essential for administrative tasks, support operations, and cross-tenant management.

## HTTP Headers

### X-Operation-Tenant-Id
- **Purpose**: Specifies the target tenant for cross-tenant operations
- **Allowed for**: SuperAdmin only
- **Format**: String (tenant identifier)
- **Example**: `X-Operation-Tenant-Id: tenant-12345`

### X-Operation-Client-Id
- **Purpose**: Specifies the target client for cross-client operations
- **Allowed for**: SuperAdmin, TenantAdmin
- **Format**: String (client identifier)
- **Example**: `X-Operation-Client-Id: client-67890`

## User Type Permissions

### SuperAdmin
- ✅ Can set `X-Operation-Tenant-Id`
- ✅ Can set `X-Operation-Client-Id`
- ✅ Can set both headers simultaneously
- **Use Cases**:
  - Platform-wide administrative tasks
  - Cross-tenant data migration
  - Support operations across any tenant/client
  - System-wide reporting and analytics

### TenantAdmin
- ❌ Cannot set `X-Operation-Tenant-Id`
- ✅ Can set `X-Operation-Client-Id` (within their tenant only)
- **Use Cases**:
  - Managing clients within their tenant
  - Tenant-level support operations
  - Client configuration and setup
  - Tenant-specific reporting

### ClientUser
- ❌ Cannot use any operational context headers
- **Restrictions**: Any attempt to use operational headers will result in `UnauthorizedAccessException`

## Usage Examples

### SuperAdmin Cross-Tenant Operation
```http
GET /api/accounting/reports
Authorization: Bearer [superadmin-jwt-token]
X-Operation-Tenant-Id: tenant-abc123
X-Operation-Client-Id: client-def456
```

### TenantAdmin Cross-Client Operation
```http
POST /api/clients/settings
Authorization: Bearer [tenantadmin-jwt-token]
X-Operation-Client-Id: client-xyz789
Content-Type: application/json

{
  "setting": "value"
}
```

## Implementation Guide

### 1. Choose Your Implementation

#### Synchronous Implementation (Default)
Use when database validation is not required:
```csharp
services.AddScoped<IOperationalContextResolver, OperationalContextResolver>();
```

#### Asynchronous Implementation (With Validation)
Use when you need database validation for client-tenant relationships:
```csharp
services.AddScoped<IClientTenantValidator, YourClientTenantValidator>();
services.AddScoped<IOperationalContextResolverAsync, OperationalContextResolverAsync>();
```

### 2. Inject the Resolver
```csharp
public class AccountingService
{
    private readonly IOperationalContextResolverAsync _contextResolver;
    private readonly IAuthorizationContext _authContext;

    public AccountingService(
        IOperationalContextResolverAsync contextResolver,
        IAuthorizationContext authContext)
    {
        _contextResolver = contextResolver;
        _authContext = authContext;
    }
}
```

### 3. Resolve Operational Context
```csharp
public async Task<IActionResult> GetReports([FromServices] HttpContext httpContext)
{
    // Resolve the operational context (async version)
    var operationalContext = await _contextResolver.ResolveContextAsync(httpContext, _authContext);

    // Get effective IDs
    var effectiveTenantId = operationalContext.GetEffectiveTenantId(_authContext.TenantId);
    var effectiveClientId = operationalContext.GetEffectiveClientId(_authContext.ClientId);

    // Use effective IDs for data access
    var reports = await _reportService.GetReports(effectiveTenantId, effectiveClientId);

    return Ok(reports);
}
```

### 4. Implement Client-Tenant Validator
```csharp
public class ClientTenantValidator : IClientTenantValidator
{
    private readonly IDbContext _dbContext;

    public async Task<bool> ValidateClientBelongsToTenantAsync(
        string clientId, string tenantId, CancellationToken cancellationToken)
    {
        return await _dbContext.Clients
            .AnyAsync(c => c.Id == clientId && c.TenantId == tenantId, cancellationToken);
    }

    public async Task<bool> TenantExistsAsync(string tenantId, CancellationToken cancellationToken)
    {
        return await _dbContext.Tenants
            .AnyAsync(t => t.Id == tenantId, cancellationToken);
    }

    public async Task<bool> ClientExistsAsync(string clientId, CancellationToken cancellationToken)
    {
        return await _dbContext.Clients
            .AnyAsync(c => c.Id == clientId, cancellationToken);
    }
}
```

### 5. Check Operational Context Status
```csharp
if (operationalContext.IsOperationalContext)
{
    // Log operational context usage for audit
    _logger.LogInformation(
        "Operational context used by {UserId} for tenant {TenantId} and client {ClientId}",
        _authContext.UserId,
        operationalContext.OperationTenantId,
        operationalContext.OperationClientId);
}
```

## Security Considerations

1. **Validation**: All operational context headers are validated against the user's permissions
2. **Audit Logging**: All operational context usage is logged for security auditing
3. **Tenant Isolation**: TenantAdmin users cannot access data outside their tenant
4. **Error Handling**: Unauthorized attempts throw `UnauthorizedAccessException`
5. **Header Sanitization**: Headers are trimmed and validated for proper format
6. **Rate Limiting**: Consider implementing rate limiting for operational context usage to prevent abuse

### Rate Limiting Recommendations

To prevent abuse of the operational context feature, implement rate limiting:

```csharp
// Example using ASP.NET Core rate limiting
services.AddRateLimiter(options =>
{
    options.AddPolicy("OperationalContext", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.User?.Identity?.Name ?? "anonymous",
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100, // 100 requests with operational headers
                Window = TimeSpan.FromMinutes(1)
            }));
});

// Apply to endpoints using operational context
app.MapControllers()
   .RequireRateLimiting("OperationalContext");
```

Consider different limits based on user type:
- **SuperAdmin**: Higher limits (e.g., 500/minute)
- **TenantAdmin**: Moderate limits (e.g., 100/minute)
- **ClientUser**: Not applicable (headers are blocked)

## Error Scenarios

### Unauthorized Tenant Access
```
Status: 401 Unauthorized
Message: User [userId] is not authorized to perform operations in the specified context
```

### Invalid User Type
```
Status: 401 Unauthorized
Message: ClientUser cannot use operational context headers
```

### Missing Tenant Context for TenantAdmin
```
Status: 401 Unauthorized
Message: TenantAdmin without tenant context cannot use operational headers
```

## Best Practices

1. **Always validate** operational access before performing sensitive operations
2. **Log all usage** of operational context for audit trails
3. **Use effective IDs** from `GetEffectiveTenantId()` and `GetEffectiveClientId()`
4. **Handle exceptions** gracefully and provide meaningful error messages
5. **Test thoroughly** with different user types and permission combinations

## Integration with API Gateway

The API Gateway should forward these headers to downstream services:

```csharp
// In API Gateway configuration
services.AddReverseProxy()
    .LoadFromConfig(Configuration.GetSection("ReverseProxy"))
    .AddTransforms(builderContext =>
    {
        // Forward operational context headers
        builderContext.AddRequestHeader("X-Operation-Tenant-Id", ForwardMode.Preserve);
        builderContext.AddRequestHeader("X-Operation-Client-Id", ForwardMode.Preserve);
    });
```

## Testing

Use the provided unit tests to validate operational context behavior:

```bash
dotnet test --filter "FullyQualifiedName~OperationalContext"
```

## Related Components

- `IAuthorizationContext`: Provides user authentication and permission data
- `IScopeResolver`: Determines authorization scopes for permissions
- `ScopeBasedAuthorizationService`: Enforces scope-based authorization rules