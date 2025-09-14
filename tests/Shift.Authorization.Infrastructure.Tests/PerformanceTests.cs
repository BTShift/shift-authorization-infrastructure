using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shift.Authorization.Infrastructure.Configuration;
using Shift.Authorization.Infrastructure.Extensions;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

/// <summary>
/// Performance tests for authorization components
/// </summary>
public class PerformanceTests
{
    [Fact]
    public void AuthorizationContext_PermissionLookup_PerformsWellWithManyPermissions()
    {
        // Arrange
        var permissions = Enumerable.Range(1, 10000)
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

        // Test 1000 permission checks
        for (int i = 1; i <= 1000; i++)
        {
            var hasPermission = context.HasPermission($"permission:{i}", AuthorizationScope.Platform);
            hasPermission.Should().BeTrue();
        }

        stopwatch.Stop();

        // Should complete in reasonable time (adjust threshold as needed)
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(100,
            "Permission lookups should be fast even with many permissions");
    }

    [Fact]
    public void AuthorizationContext_Creation_PerformsWellWithManyClaims()
    {
        // Arrange - Create many claims
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("user_type", "SuperAdmin"),
            new("tenant_id", "tenant456"),
            new("client_id", "client789")
        };

        // Add many permission claims
        for (int i = 1; i <= 1000; i++)
        {
            claims.Add(new Claim("permission", $"permission:{i}"));
        }

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act & Assert
        var stopwatch = Stopwatch.StartNew();

        for (int i = 0; i < 100; i++)
        {
            var context = new AuthorizationContext(claimsPrincipal);
            context.Permissions.Should().HaveCount(1000);
        }

        stopwatch.Stop();

        // Should create contexts quickly even with many claims
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(500,
            "AuthorizationContext creation should be fast even with many claims");
    }

    [Fact]
    public async Task AuthorizationContext_ConcurrentAccess_IsThreadSafe()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: Enumerable.Range(1, 100).Select(i => $"permission:{i}").ToList());

        var exceptions = new List<Exception>();
        var tasks = new List<Task>();

        // Act - Multiple threads accessing context concurrently
        for (int i = 0; i < 20; i++)
        {
            var threadId = i;
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (int j = 0; j < 1000; j++)
                    {
                        // Read operations should be thread-safe
                        _ = context.UserId;
                        _ = context.TenantId;
                        _ = context.UserType;
                        _ = context.Permissions.Count;
                        _ = context.HasPermission($"permission:{j % 100 + 1}", AuthorizationScope.Platform);
                        _ = context.CanAccessTenant("tenant456");
                        _ = context.CanAccessClient("client789");
                    }
                }
                catch (Exception ex)
                {
                    lock (exceptions)
                    {
                        exceptions.Add(new Exception($"Thread {threadId}: {ex.Message}", ex));
                    }
                }
            }));
        }

        await Task.WhenAll(tasks.ToArray());

        // Assert
        exceptions.Should().BeEmpty("AuthorizationContext should be thread-safe for read operations");
    }

    [Fact]
    public async Task ScopeResolver_PerformanceWithManyContexts()
    {
        // Arrange
        var resolver = new ScopeResolver();
        var contexts = new List<IAuthorizationContext>();

        // Create many different contexts
        for (int i = 0; i < 1000; i++)
        {
            var userType = (UserType)(i % 3); // Cycle through user types
            contexts.Add(new AuthorizationContext(
                userId: $"user{i}",
                tenantId: $"tenant{i / 10}",
                clientId: $"client{i}",
                userType: userType,
                permissions: new List<string> { $"permission:{i}" }));
        }

        // Act & Assert
        var stopwatch = Stopwatch.StartNew();

        await Task.Run(() =>
        {
            foreach (var context in contexts)
            {
                var scope = resolver.GetMaximumScope(context.UserType);
                scope.Should().BeOneOf(AuthorizationScope.Platform, AuthorizationScope.Tenant, AuthorizationScope.Own);
            }
        });

        stopwatch.Stop();

        // Should resolve scopes quickly
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(100,
            "ScopeResolver should be fast when processing many contexts");
    }

    [Fact]
    public void PermissionScopeMapping_LookupPerformance()
    {
        // Arrange - Create many permission mappings
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddShiftAuthorization();

        for (int i = 1; i <= 1000; i++)
        {
            services.AddPermissionScopeMapping($"permission:{i}", AuthorizationScope.Tenant);
        }

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        // Create context with all these permissions
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.TenantAdmin,
            permissions: Enumerable.Range(1, 1000).Select(i => $"permission:{i}").ToList());

        // Act & Assert
        var stopwatch = Stopwatch.StartNew();

        for (int i = 1; i <= 1000; i++)
        {
            var requiredScope = context.GetRequiredScope($"permission:{i}");
            requiredScope.Should().Be(AuthorizationScope.Tenant);
        }

        stopwatch.Stop();

        // Should lookup permission scopes quickly
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(50,
            "Permission scope lookups should be fast even with many mappings");
    }

    [Fact]
    public void AuthorizationContext_MemoryUsage_IsReasonable()
    {
        // Arrange & Act
        var contexts = new List<IAuthorizationContext>();

        // Create many contexts to test memory usage
        for (int i = 0; i < 1000; i++)
        {
            contexts.Add(new AuthorizationContext(
                userId: $"user{i}",
                tenantId: $"tenant{i / 10}",
                clientId: $"client{i}",
                userType: UserType.TenantAdmin,
                permissions: Enumerable.Range(1, 10).Select(j => $"permission:{j}").ToList()));
        }

        // Force garbage collection to get accurate memory measurement
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var memoryBefore = GC.GetTotalMemory(false);

        // Create more contexts
        var additionalContexts = new List<IAuthorizationContext>();
        for (int i = 0; i < 1000; i++)
        {
            additionalContexts.Add(new AuthorizationContext(
                userId: $"user{i + 1000}",
                tenantId: $"tenant{(i + 1000) / 10}",
                clientId: $"client{i + 1000}",
                userType: UserType.ClientUser,
                permissions: Enumerable.Range(1, 10).Select(j => $"permission:{j}").ToList()));
        }

        var memoryAfter = GC.GetTotalMemory(false);
        var memoryIncrease = memoryAfter - memoryBefore;

        // Assert - Memory usage per context should be reasonable
        var averageMemoryPerContext = memoryIncrease / 1000.0;
        averageMemoryPerContext.Should().BeLessThan(10000, // 10KB per context seems reasonable
            "Memory usage per AuthorizationContext should be reasonable");

        // Cleanup
        contexts.Clear();
        additionalContexts.Clear();
        GC.Collect();
    }

    [Fact]
    public void AuthorizationContext_BulkPermissionChecks_PerformsWell()
    {
        // Arrange
        var permissions = Enumerable.Range(1, 500)
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

        // Check all permissions multiple times
        for (int iteration = 0; iteration < 10; iteration++)
        {
            var results = permissions.Select(p => context.HasPermission(p, AuthorizationScope.Platform)).ToList();
            results.Should().AllSatisfy(result => result.Should().BeTrue());
        }

        stopwatch.Stop();

        // Should complete bulk checks quickly
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(100,
            "Bulk permission checks should be fast");
    }

    [Fact]
    public void AuthorizationContext_StringComparisons_AreOptimized()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string> { "permission:test" });

        // Act & Assert - Test case sensitivity performance
        var stopwatch = Stopwatch.StartNew();

        for (int i = 0; i < 10000; i++)
        {
            // These should be fast case-sensitive comparisons
            context.HasPermission("permission:test", AuthorizationScope.Platform).Should().BeTrue();
            context.HasPermission("PERMISSION:TEST", AuthorizationScope.Platform).Should().BeFalse();
            context.HasPermission("Permission:Test", AuthorizationScope.Platform).Should().BeFalse();
        }

        stopwatch.Stop();

        // String comparisons should be fast
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(50,
            "String comparisons for permission checks should be optimized");
    }

    [Theory]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(5000)]
    public void AuthorizationContext_ScalesWithPermissionCount(int permissionCount)
    {
        // Arrange
        var permissions = Enumerable.Range(1, permissionCount)
            .Select(i => $"permission:{i}")
            .ToList();

        // Act & Assert - Creation time should scale reasonably
        var stopwatch = Stopwatch.StartNew();

        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: permissions);

        var creationTime = stopwatch.ElapsedMilliseconds;

        // Test permission lookup time
        stopwatch.Restart();

        var hasFirstPermission = context.HasPermission("permission:1", AuthorizationScope.Platform);
        var hasLastPermission = context.HasPermission($"permission:{permissionCount}", AuthorizationScope.Platform);

        var lookupTime = stopwatch.ElapsedMilliseconds;

        // Assert reasonable performance scaling
        creationTime.Should().BeLessThan(permissionCount / 10 + 100,
            $"Creation time should scale reasonably with {permissionCount} permissions");

        lookupTime.Should().BeLessThan(10,
            "Permission lookups should be fast regardless of total permission count");

        hasFirstPermission.Should().BeTrue();
        hasLastPermission.Should().BeTrue();
    }

    [Fact]
    public async Task ParallelContextCreation_PerformsWell()
    {
        // Arrange
        const int contextCount = 1000;
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("user_type", "TenantAdmin"),
            new("tenant_id", "tenant456"),
            new("permission", "read"),
            new("permission", "write")
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var stopwatch = Stopwatch.StartNew();

        var tasks = Enumerable.Range(0, contextCount)
            .Select(_ => Task.Run(() => new AuthorizationContext(claimsPrincipal)))
            .ToArray();

        var contexts = await Task.WhenAll(tasks);

        stopwatch.Stop();

        // Assert
        contexts.Should().HaveCount(contextCount);
        contexts.Should().AllSatisfy(c =>
        {
            c.UserId.Should().Be("user123");
            c.UserType.Should().Be(UserType.TenantAdmin);
            c.TenantId.Should().Be("tenant456");
            c.Permissions.Should().HaveCount(2);
        });

        // Parallel creation should still be reasonably fast
        var averageCreationTime = (double)stopwatch.ElapsedMilliseconds / contextCount;
        averageCreationTime.Should().BeLessThan(1.0,
            "Parallel context creation should be efficient");
    }
}