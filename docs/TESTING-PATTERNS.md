# Testing Patterns and Best Practices

This document outlines the testing patterns and best practices for the Shift Authorization Infrastructure.

## Table of Contents

- [Test Organization](#test-organization)
- [Unit Testing Patterns](#unit-testing-patterns)
- [Integration Testing](#integration-testing)
- [Mock Scenarios](#mock-scenarios)
- [Performance Testing](#performance-testing)
- [Test Data Management](#test-data-management)
- [Common Patterns](#common-patterns)
- [Testing Anti-Patterns](#testing-anti-patterns)

## Test Organization

### Test Structure

```
tests/
├── Shift.Authorization.Infrastructure.Tests/
│   ├── Unit Tests/
│   │   ├── AuthorizationContextTests.cs
│   │   ├── ScopeResolverTests.cs
│   │   └── OperationalContextResolverTests.cs
│   ├── Integration Tests/
│   │   ├── AuthorizationContextMiddlewareIntegrationTests.cs
│   │   └── ServiceCollectionExtensionsTests.cs
│   ├── Scenario Tests/
│   │   ├── AuthorizationScenariosTests.cs
│   │   ├── OperationalContextScenariosTests.cs
│   │   └── MockScenariosTests.cs
│   ├── Performance Tests/
│   │   └── PerformanceTests.cs
│   └── Edge Cases/
│       └── EdgeCasesAndErrorHandlingTests.cs
```

### Test Categories

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions
3. **Scenario Tests**: Test real-world authorization scenarios
4. **Performance Tests**: Validate performance characteristics
5. **Edge Case Tests**: Test boundary conditions and error handling

## Unit Testing Patterns

### Testing Authorization Context Creation

```csharp
[Fact]
public void AuthorizationContext_WithValidClaims_CreatesCorrectContext()
{
    // Arrange
    var claims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, "user123"),
        new("user_type", "TenantAdmin"),
        new("tenant_id", "tenant456"),
        new("permission", "read")
    };
    var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

    // Act
    var context = new AuthorizationContext(claimsPrincipal);

    // Assert
    context.UserId.Should().Be("user123");
    context.UserType.Should().Be(UserType.TenantAdmin);
    context.TenantId.Should().Be("tenant456");
    context.Permissions.Should().Contain("read");
}
```

### Testing Permission Checks

```csharp
[Theory]
[InlineData(UserType.SuperAdmin, AuthorizationScope.Platform, true)]
[InlineData(UserType.TenantAdmin, AuthorizationScope.Platform, false)]
[InlineData(UserType.TenantAdmin, AuthorizationScope.Tenant, true)]
[InlineData(UserType.ClientUser, AuthorizationScope.Own, true)]
public void HasPermission_WithDifferentUserTypesAndScopes_ReturnsExpectedResult(
    UserType userType, AuthorizationScope scope, bool expected)
{
    // Arrange
    var context = CreateTestContext(userType, permissions: new[] { "test:permission" });

    // Act
    var result = context.HasPermission("test:permission", scope);

    // Assert
    result.Should().Be(expected);
}
```

### Testing Error Conditions

```csharp
[Fact]
public void AuthorizationContext_WithNullClaimsPrincipal_ThrowsArgumentNullException()
{
    // Act & Assert
    var action = () => new AuthorizationContext(null!);
    action.Should().Throw<ArgumentNullException>();
}

[Theory]
[InlineData("")]
[InlineData(" ")]
[InlineData(null)]
public void HasPermission_WithInvalidPermission_ThrowsArgumentException(string permission)
{
    // Arrange
    var context = CreateTestContext(UserType.SuperAdmin);

    // Act & Assert
    var action = () => context.HasPermission(permission!, AuthorizationScope.Own);
    action.Should().Throw<ArgumentException>();
}
```

## Integration Testing

### Testing Middleware Pipeline

```csharp
public class AuthorizationContextMiddlewareIntegrationTests : IAsyncLifetime
{
    private WebApplication? _app;
    private HttpClient? _client;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();

        // Configure services
        builder.Services.AddShiftAuthorization(options =>
        {
            options.JwtValidationKey = "test-key";
            options.JwtIssuer = "test-issuer";
            options.JwtAudience = "test-audience";
        });

        _app = builder.Build();
        _app.UseShiftAuthorization();

        // Add test endpoints
        _app.MapGet("/test", (IServiceProvider serviceProvider) =>
        {
            var contextService = serviceProvider.GetRequiredService<AuthorizationContextService>();
            var context = contextService.Context;
            return context != null ? Results.Ok(context) : Results.Unauthorized();
        });

        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    [Fact]
    public async Task Middleware_WithValidJwt_SetsAuthorizationContext()
    {
        // Arrange
        var token = GenerateTestJwt("user123", UserType.TenantAdmin);
        var request = new HttpRequestMessage(HttpMethod.Get, "/test");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client!.SendAsync(request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        // Additional assertions on response content
    }
}
```

### Testing Service Registration

```csharp
[Fact]
public void AddShiftAuthorization_RegistersRequiredServices()
{
    // Arrange
    var services = new ServiceCollection();
    services.AddLogging();

    // Act
    services.AddShiftAuthorization();
    var provider = services.BuildServiceProvider();

    // Assert
    provider.GetService<AuthorizationContextService>().Should().NotBeNull();
    provider.GetService<IScopeResolver>().Should().NotBeNull();
    provider.GetService<ScopeBasedAuthorizationService>().Should().NotBeNull();
}
```

## Mock Scenarios

### Testing Service Integration Patterns

```csharp
public class MockScenariosTests
{
    [Fact]
    public void MockScenario_MultiTenantService_SuperAdminCrossTenantAccess()
    {
        // Scenario: SuperAdmin accessing different tenants

        // Arrange
        var superAdminContext = CreateContext(UserType.SuperAdmin,
            permissions: new[] { "platform:admin", "tenant:read" });
        var tenantService = new MockTenantService();

        // Act & Assert - SuperAdmin can access any tenant
        tenantService.GetTenantData("tenant-a", superAdminContext).Should().NotBeNull();
        tenantService.GetTenantData("tenant-b", superAdminContext).Should().NotBeNull();
    }

    [Fact]
    public void MockScenario_TenantAdminBoundaryViolation_ThrowsUnauthorized()
    {
        // Scenario: TenantAdmin attempting cross-tenant access

        // Arrange
        var tenantAdminContext = CreateContext(UserType.TenantAdmin,
            tenantId: "tenant-a", permissions: new[] { "tenant:read" });
        var tenantService = new MockTenantService();

        // Act & Assert - TenantAdmin cannot access different tenant
        var action = () => tenantService.GetTenantData("tenant-b", tenantAdminContext);
        action.Should().Throw<UnauthorizedAccessException>();
    }
}

// Mock service implementation
public class MockTenantService
{
    public object GetTenantData(string tenantId, IAuthorizationContext context)
    {
        if (!context.HasPermission("tenant:read", AuthorizationScope.Tenant) ||
            !context.CanAccessTenant(tenantId))
        {
            throw new UnauthorizedAccessException($"Cannot access tenant {tenantId}");
        }

        return new { TenantId = tenantId, Data = "tenant-data" };
    }
}
```

## Performance Testing

### Testing Authorization Performance

```csharp
[Theory]
[InlineData(10)]
[InlineData(100)]
[InlineData(1000)]
public void AuthorizationContext_PerformanceWithManyPermissions(int permissionCount)
{
    // Arrange
    var permissions = Enumerable.Range(1, permissionCount)
        .Select(i => $"permission:{i}")
        .ToList();

    var context = new AuthorizationContext(
        userId: "user123",
        tenantId: "tenant456",
        clientId: "client789",
        userType: UserType.SuperAdmin,
        permissions: permissions);

    // Act & Assert
    var stopwatch = Stopwatch.StartNew();

    for (int i = 1; i <= 100; i++)
    {
        context.HasPermission($"permission:{i}", AuthorizationScope.Platform);
    }

    stopwatch.Stop();

    // Should complete within reasonable time
    stopwatch.ElapsedMilliseconds.Should().BeLessThan(50);
}
```

### Testing Concurrent Access

```csharp
[Fact]
public void AuthorizationContext_ConcurrentAccess_IsThreadSafe()
{
    // Arrange
    var context = CreateTestContext(UserType.SuperAdmin);
    var exceptions = new ConcurrentBag<Exception>();
    var tasks = new List<Task>();

    // Act - Multiple threads accessing context
    for (int i = 0; i < 10; i++)
    {
        tasks.Add(Task.Run(() =>
        {
            try
            {
                for (int j = 0; j < 1000; j++)
                {
                    _ = context.UserId;
                    _ = context.HasPermission("test:permission", AuthorizationScope.Platform);
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));
    }

    Task.WaitAll(tasks.ToArray());

    // Assert
    exceptions.Should().BeEmpty();
}
```

## Test Data Management

### Helper Methods for Test Context Creation

```csharp
public static class TestHelpers
{
    public static IAuthorizationContext CreateContext(
        UserType userType,
        string? tenantId = null,
        string? clientId = null,
        string[]? permissions = null)
    {
        return new AuthorizationContext(
            userId: $"user-{userType}",
            tenantId: tenantId,
            clientId: clientId,
            userType: userType,
            permissions: permissions?.ToList() ?? new List<string>());
    }

    public static ClaimsPrincipal CreateClaimsPrincipal(
        string userId,
        UserType userType,
        string? tenantId = null,
        string? clientId = null,
        params string[] permissions)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new("user_type", userType.ToString())
        };

        if (!string.IsNullOrEmpty(tenantId))
            claims.Add(new Claim("tenant_id", tenantId));

        if (!string.IsNullOrEmpty(clientId))
            claims.Add(new Claim("client_id", clientId));

        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims));
    }

    public static string GenerateTestJwt(
        string userId,
        UserType userType,
        string? tenantId = null,
        string? clientId = null,
        params string[] permissions)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes("test-secret-key-with-minimum-256-bits-length!");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("user_type", userType.ToString())
        };

        if (!string.IsNullOrEmpty(tenantId))
            claims.Add(new Claim("tenant_id", tenantId));

        if (!string.IsNullOrEmpty(clientId))
            claims.Add(new Claim("client_id", clientId));

        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(60),
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
```

## Common Patterns

### Testing All User Types with Theory

```csharp
[Theory]
[InlineData(UserType.SuperAdmin)]
[InlineData(UserType.TenantAdmin)]
[InlineData(UserType.ClientUser)]
public void AllUserTypes_ShouldHandleBasicOperations(UserType userType)
{
    // Arrange
    var context = TestHelpers.CreateContext(userType);

    // Act & Assert - Basic operations should work for all user types
    context.UserId.Should().NotBeNullOrEmpty();
    context.UserType.Should().Be(userType);

    // User-type specific assertions
    switch (userType)
    {
        case UserType.SuperAdmin:
            // SuperAdmin specific tests
            break;
        case UserType.TenantAdmin:
            // TenantAdmin specific tests
            break;
        case UserType.ClientUser:
            // ClientUser specific tests
            break;
    }
}
```

### Testing Scope Hierarchy

```csharp
[Fact]
public void ScopeHierarchy_SuperAdminCanAccessAllScopes()
{
    // Arrange
    var context = TestHelpers.CreateContext(UserType.SuperAdmin,
        permissions: new[] { "test:permission" });

    // Assert - SuperAdmin can access all scopes
    context.HasPermission("test:permission", AuthorizationScope.Platform).Should().BeTrue();
    context.HasPermission("test:permission", AuthorizationScope.Tenant).Should().BeTrue();
    context.HasPermission("test:permission", AuthorizationScope.Own).Should().BeTrue();
}
```

## Testing Anti-Patterns

### ❌ Don't: Hard-code test values

```csharp
// Bad
var context = new AuthorizationContext("user123", "tenant456", "client789", ...);
```

### ✅ Do: Use helper methods

```csharp
// Good
var context = TestHelpers.CreateContext(UserType.TenantAdmin,
    tenantId: "tenant456", permissions: new[] { "read", "write" });
```

### ❌ Don't: Test implementation details

```csharp
// Bad - testing internal dictionary structure
context._permissionScopes.Should().ContainKey("read");
```

### ✅ Do: Test public behavior

```csharp
// Good - testing public API
context.HasPermission("read", AuthorizationScope.Tenant).Should().BeTrue();
```

### ❌ Don't: Create brittle tests

```csharp
// Bad - brittle timing assertion
stopwatch.ElapsedMilliseconds.Should().Be(10);
```

### ✅ Do: Use reasonable thresholds

```csharp
// Good - reasonable performance threshold
stopwatch.ElapsedMilliseconds.Should().BeLessThan(100);
```

### ❌ Don't: Ignore edge cases

```csharp
// Bad - only testing happy path
[Fact]
public void HasPermission_WithValidInput_ReturnsTrue() { ... }
```

### ✅ Do: Test edge cases and error conditions

```csharp
// Good - comprehensive testing
[Theory]
[InlineData(null)]
[InlineData("")]
[InlineData(" ")]
public void HasPermission_WithInvalidInput_ThrowsException(string permission) { ... }
```

## Best Practices Summary

1. **Use Theory tests** for testing multiple similar scenarios
2. **Create helper methods** for common test setup
3. **Test edge cases and error conditions** explicitly
4. **Use descriptive test names** that explain the scenario
5. **Arrange-Act-Assert pattern** for clarity
6. **Mock external dependencies** for unit tests
7. **Test performance characteristics** for critical paths
8. **Verify thread safety** for shared components
9. **Use realistic test data** that reflects actual usage
10. **Keep tests independent** and isolated

## Running Tests

### All Tests
```bash
dotnet test
```

### Specific Category
```bash
dotnet test --filter Category=Performance
dotnet test --filter Category=Integration
```

### With Coverage
```bash
dotnet test --collect:"XPlat Code Coverage"
```

### Performance Tests Only
```bash
dotnet test --filter ClassName~PerformanceTests
```