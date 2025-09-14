# Examples

This directory contains practical examples of using the Shift.Authorization.Infrastructure package.

## Available Examples

### Basic Authorization Check

```csharp
public class InvoiceService
{
    private readonly IAuthorizationContext _authContext;

    public InvoiceService(IAuthorizationContext authContext)
    {
        _authContext = authContext;
    }

    public async Task<Invoice> GetInvoiceAsync(int invoiceId)
    {
        // Check if user has read permissions
        if (!_authContext.HasScope("accounting.invoices.read"))
        {
            throw new UnauthorizedAccessException("Insufficient permissions to read invoices");
        }

        // Ensure invoice belongs to user's tenant
        var invoice = await _repository.GetByIdAsync(invoiceId);
        if (invoice.TenantId != _authContext.TenantId)
        {
            throw new UnauthorizedAccessException("Invoice not found in current tenant context");
        }

        return invoice;
    }
}
```

### Multi-Scope Authorization

```csharp
public class AccountingController : ControllerBase
{
    private readonly IAuthorizationContext _authContext;

    [HttpPost("invoices")]
    public async Task<IActionResult> CreateInvoice([FromBody] CreateInvoiceRequest request)
    {
        // Check multiple scopes for invoice creation
        var requiredScopes = new[]
        {
            "accounting.invoices.write",
            "accounting.clients.read"
        };

        foreach (var scope in requiredScopes)
        {
            if (!_authContext.HasScope(scope))
            {
                return Forbid($"Missing required scope: {scope}");
            }
        }

        // Proceed with invoice creation...
        var invoice = await _invoiceService.CreateAsync(request, _authContext.TenantId);
        return Ok(invoice);
    }
}
```

### Conditional Authorization

```csharp
public class UserService
{
    private readonly IAuthorizationContext _authContext;

    public async Task<User[]> GetUsersAsync()
    {
        // Platform admins can see all users across tenants
        if (_authContext.HasScope("platform.admin"))
        {
            return await _repository.GetAllUsersAsync();
        }

        // Tenant admins can see users in their tenant
        if (_authContext.HasScope("tenant.users.read"))
        {
            return await _repository.GetUsersByTenantAsync(_authContext.TenantId);
        }

        // Regular users can only see themselves
        if (_authContext.HasScope("user.profile.read"))
        {
            var user = await _repository.GetByIdAsync(_authContext.UserId);
            return new[] { user };
        }

        throw new UnauthorizedAccessException("No permission to read user data");
    }
}
```

### gRPC Service Integration

```csharp
[Authorize]
public class AccountingServiceImpl : AccountingService.AccountingServiceBase
{
    private readonly IAuthorizationContext _authContext;

    public override async Task<GetInvoicesResponse> GetInvoices(
        GetInvoicesRequest request,
        ServerCallContext context)
    {
        // Authorization context automatically populated from gRPC metadata
        if (!_authContext.HasScope("accounting.invoices.read"))
        {
            throw new RpcException(new Status(StatusCode.PermissionDenied,
                "Insufficient permissions"));
        }

        var invoices = await _invoiceService.GetByTenantAsync(_authContext.TenantId);

        return new GetInvoicesResponse
        {
            Invoices = { invoices.Select(MapToProto) }
        };
    }
}
```

## Running the Examples

These examples assume proper dependency injection setup. See the main documentation for complete configuration details.

## Integration Patterns

For more complex integration scenarios, see:
- [Service Integration Guide](../docs/guides/service-integration.md)
- [Multi-Tenant Patterns](../docs/multi-tenant.md)
- [Best Practices](../docs/guides/best-practices.md)