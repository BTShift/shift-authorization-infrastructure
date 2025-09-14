using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class ScopeResolverTests
{
    private readonly ScopeResolver _scopeResolver;
    private readonly List<PermissionScopeMapping> _testMappings;

    public ScopeResolverTests()
    {
        _testMappings = new List<PermissionScopeMapping>
        {
            new()
            {
                Permission = "platform:admin",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"]
            },
            new()
            {
                Permission = "tenant:read",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"]
            },
            new()
            {
                Permission = "client:read",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"]
            }
        };
        _scopeResolver = new ScopeResolver(_testMappings);
    }

    [Fact]
    public void Constructor_WithNullMappings_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new ScopeResolver(null!));
    }

    [Fact]
    public void Constructor_WithEmptyMappings_ShouldNotThrow()
    {
        var exception = Record.Exception(() => new ScopeResolver(new List<PermissionScopeMapping>()));
        Assert.Null(exception);
    }

    [Fact]
    public void DefaultConstructor_ShouldCreateInstanceWithDefaultMappings()
    {
        var resolver = new ScopeResolver();

        // Test some well-known permissions from default mappings
        Assert.Equal(AuthorizationScope.Platform, resolver.GetRequiredScope("platform:admin"));
        Assert.Equal(AuthorizationScope.Tenant, resolver.GetRequiredScope("tenant:read"));
        Assert.Equal(AuthorizationScope.Own, resolver.GetRequiredScope("client:read"));
    }

    [Theory]
    [InlineData("platform:admin", AuthorizationScope.Platform)]
    [InlineData("tenant:read", AuthorizationScope.Tenant)]
    [InlineData("client:read", AuthorizationScope.Own)]
    public void GetRequiredScope_WithKnownPermissions_ShouldReturnCorrectScope(string permission, AuthorizationScope expectedScope)
    {
        var result = _scopeResolver.GetRequiredScope(permission);
        Assert.Equal(expectedScope, result);
    }

    [Fact]
    public void GetRequiredScope_WithUnknownPermission_ShouldReturnOwnScope()
    {
        var result = _scopeResolver.GetRequiredScope("unknown:permission");
        Assert.Equal(AuthorizationScope.Own, result);
    }

    [Fact]
    public void GetRequiredScope_WithNullPermission_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _scopeResolver.GetRequiredScope(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void GetRequiredScope_WithEmptyPermission_ShouldThrowArgumentException(string permission)
    {
        Assert.Throws<ArgumentException>(() => _scopeResolver.GetRequiredScope(permission));
    }

    [Theory]
    [InlineData(AuthorizationScope.Platform, "platform:admin")]
    [InlineData(AuthorizationScope.Tenant, "tenant:read")]
    [InlineData(AuthorizationScope.Own, "client:read")]
    public void GetPermissionsForScope_ShouldReturnCorrectPermissions(AuthorizationScope scope, string expectedPermission)
    {
        var permissions = _scopeResolver.GetPermissionsForScope(scope);
        Assert.Contains(expectedPermission, permissions);
    }

    [Fact]
    public void GetPermissionsForScope_WithNonExistentScope_ShouldReturnEmptyList()
    {
        // Create resolver with no mappings for a specific scope
        var mappings = new List<PermissionScopeMapping>
        {
            new() { Permission = "test", RequiredScope = AuthorizationScope.Platform, AllowedUserTypes = ["SuperAdmin"] }
        };
        var resolver = new ScopeResolver(mappings);

        var permissions = resolver.GetPermissionsForScope(AuthorizationScope.Own);
        Assert.Empty(permissions);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Platform, true)]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Tenant, true)]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Own, true)]
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Platform, false)]
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Tenant, true)]
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Own, true)]
    [InlineData(UserType.ClientUser, AuthorizationScope.Platform, false)]
    [InlineData(UserType.ClientUser, AuthorizationScope.Tenant, false)]
    [InlineData(UserType.ClientUser, AuthorizationScope.Own, true)]
    public void CanOperateAtScope_ShouldReturnCorrectResult(UserType userType, AuthorizationScope scope, bool expectedResult)
    {
        var result = _scopeResolver.CanOperateAtScope(userType, scope);
        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Platform)]
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Tenant)]
    [InlineData(UserType.ClientUser, AuthorizationScope.Own)]
    public void GetMaximumScope_ShouldReturnCorrectMaximumScope(UserType userType, AuthorizationScope expectedMaxScope)
    {
        var result = _scopeResolver.GetMaximumScope(userType);
        Assert.Equal(expectedMaxScope, result);
    }

    [Theory]
    [InlineData("platform:admin")]
    [InlineData("tenant:read")]
    [InlineData("client:read")]
    public void GetPermissionMapping_WithKnownPermission_ShouldReturnMapping(string permission)
    {
        var mapping = _scopeResolver.GetPermissionMapping(permission);
        Assert.NotNull(mapping);
        Assert.Equal(permission, mapping.Permission);
    }

    [Fact]
    public void GetPermissionMapping_WithUnknownPermission_ShouldReturnNull()
    {
        var mapping = _scopeResolver.GetPermissionMapping("unknown:permission");
        Assert.Null(mapping);
    }

    [Fact]
    public void GetPermissionMapping_WithNullPermission_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _scopeResolver.GetPermissionMapping(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void GetPermissionMapping_WithEmptyPermission_ShouldThrowArgumentException(string permission)
    {
        Assert.Throws<ArgumentException>(() => _scopeResolver.GetPermissionMapping(permission));
    }

    [Theory]
    [InlineData("platform:admin", UserType.SuperAdmin, true)]
    [InlineData("platform:admin", UserType.TenantAdmin, false)]
    [InlineData("platform:admin", UserType.ClientUser, false)]
    [InlineData("tenant:read", UserType.SuperAdmin, true)]
    [InlineData("tenant:read", UserType.TenantAdmin, true)]
    [InlineData("tenant:read", UserType.ClientUser, false)]
    [InlineData("client:read", UserType.SuperAdmin, true)]
    [InlineData("client:read", UserType.TenantAdmin, true)]
    [InlineData("client:read", UserType.ClientUser, true)]
    public void IsPermissionAllowedForUserType_ShouldReturnCorrectResult(string permission, UserType userType, bool expectedResult)
    {
        var result = _scopeResolver.IsPermissionAllowedForUserType(permission, userType);
        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void IsPermissionAllowedForUserType_WithUnknownPermission_ShouldReturnFalse()
    {
        var result = _scopeResolver.IsPermissionAllowedForUserType("unknown:permission", UserType.SuperAdmin);
        Assert.False(result);
    }

    [Fact]
    public void IsPermissionAllowedForUserType_WithNullPermission_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _scopeResolver.IsPermissionAllowedForUserType(null!, UserType.SuperAdmin));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void IsPermissionAllowedForUserType_WithEmptyPermission_ShouldThrowArgumentException(string permission)
    {
        Assert.Throws<ArgumentException>(() => _scopeResolver.IsPermissionAllowedForUserType(permission, UserType.SuperAdmin));
    }

    [Fact]
    public void Constructor_WithDuplicatePermissions_ShouldUseLastMapping()
    {
        var mappingsWithDuplicates = new List<PermissionScopeMapping>
        {
            new()
            {
                Permission = "duplicate:permission",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"]
            },
            new()
            {
                Permission = "duplicate:permission",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["ClientUser"]
            }
        };

        var resolver = new ScopeResolver(mappingsWithDuplicates);

        // Should use the last mapping (Own scope, ClientUser)
        Assert.Equal(AuthorizationScope.Own, resolver.GetRequiredScope("duplicate:permission"));
        Assert.False(resolver.IsPermissionAllowedForUserType("duplicate:permission", UserType.SuperAdmin));
        Assert.True(resolver.IsPermissionAllowedForUserType("duplicate:permission", UserType.ClientUser));
    }

    [Fact]
    public void PermissionLookup_ShouldBeCaseInsensitive()
    {
        var result1 = _scopeResolver.GetRequiredScope("PLATFORM:ADMIN");
        var result2 = _scopeResolver.GetRequiredScope("platform:admin");
        var result3 = _scopeResolver.GetRequiredScope("Platform:Admin");

        Assert.Equal(result2, result1);
        Assert.Equal(result2, result3);
    }
}