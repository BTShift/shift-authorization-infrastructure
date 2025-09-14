using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class ScopeBasedAuthorizationServiceTests
{
    private readonly ScopeResolver _scopeResolver;
    private readonly ScopeBasedAuthorizationService _authService;

    public ScopeBasedAuthorizationServiceTests()
    {
        var testMappings = new List<PermissionScopeMapping>
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
        _scopeResolver = new ScopeResolver(testMappings);
        _authService = new ScopeBasedAuthorizationService(_scopeResolver);
    }

    [Fact]
    public void Constructor_WithNullScopeResolver_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new ScopeBasedAuthorizationService(null!));
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "platform:admin", true)]
    [InlineData(UserType.TenantAdmin, "platform:admin", false)] // TenantAdmin doesn't have permission
    [InlineData(UserType.SuperAdmin, "tenant:read", true)]
    [InlineData(UserType.TenantAdmin, "tenant:read", true)]
    [InlineData(UserType.ClientUser, "tenant:read", false)] // ClientUser not allowed
    [InlineData(UserType.ClientUser, "client:read", true)]
    public void Authorize_WithPermissionOnly_ShouldReturnCorrectResult(UserType userType, string permission, bool expectedResult)
    {
        var permissions = GetPermissionsForUserType(userType);
        var context = new AuthorizationContext("user1", "tenant1", "client1", userType, permissions);

        var result = _authService.Authorize(context, permission);

        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void Authorize_WithContextWithoutPermission_ShouldReturnFalse()
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);

        var result = _authService.Authorize(context, "platform:admin");

        Assert.False(result);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Platform, true)]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Tenant, true)]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Own, true)]
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Platform, false)]
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Tenant, true)]
    [InlineData(UserType.ClientUser, AuthorizationScope.Own, true)]
    public void Authorize_WithExplicitScope_ShouldReturnCorrectResult(UserType userType, AuthorizationScope scope, bool expectedResult)
    {
        var permissions = new List<string> { "test:permission" };
        var context = new AuthorizationContext("user1", "tenant1", "client1", userType, permissions);

        var result = _authService.Authorize(context, "test:permission", scope);

        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData("tenant1", true)]  // Same tenant
    [InlineData("tenant2", false)] // Different tenant
    public void AuthorizeTenantAccess_WithTenantAdmin_ShouldReturnCorrectResult(string targetTenantId, bool expectedResult)
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.TenantAdmin, []);

        var result = _authService.AuthorizeTenantAccess(context, targetTenantId);

        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData("client1", true)]  // Same client
    [InlineData("client2", false)] // Different client
    public void AuthorizeClientAccess_WithClientUser_ShouldReturnCorrectResult(string targetClientId, bool expectedResult)
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.ClientUser, []);

        var result = _authService.AuthorizeClientAccess(context, targetClientId);

        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void AuthorizeResourceAccess_WithValidContext_ShouldReturnTrue()
    {
        var permissions = new List<string> { "client:read" };
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.ClientUser, permissions);

        var result = _authService.AuthorizeResourceAccess(context, "client:read", "tenant1", "client1");

        Assert.True(result);
    }

    [Fact]
    public void AuthorizeResourceAccess_WithoutClientId_ShouldOnlyCheckTenant()
    {
        var permissions = new List<string> { "tenant:read" };
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.TenantAdmin, permissions);

        var result = _authService.AuthorizeResourceAccess(context, "tenant:read", "tenant1");

        Assert.True(result);
    }

    [Fact]
    public void AuthorizeResourceAccess_WithWrongTenant_ShouldReturnFalse()
    {
        var permissions = new List<string> { "client:read" };
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.ClientUser, permissions);

        var result = _authService.AuthorizeResourceAccess(context, "client:read", "tenant2", "client1");

        Assert.False(result);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, AuthorizationScope.Platform, 1)] // Has platform:admin
    [InlineData(UserType.TenantAdmin, AuthorizationScope.Tenant, 1)]  // Has tenant:read
    [InlineData(UserType.ClientUser, AuthorizationScope.Own, 1)]      // Has client:read
    [InlineData(UserType.ClientUser, AuthorizationScope.Platform, 0)] // No platform permissions
    public void GetAvailablePermissions_ShouldReturnCorrectCount(UserType userType, AuthorizationScope scope, int expectedCount)
    {
        var permissions = _authService.GetAvailablePermissions(userType, scope);

        Assert.Equal(expectedCount, permissions.Count);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, 3)] // Can access all 3 scopes
    [InlineData(UserType.TenantAdmin, 2)] // Can access Tenant and Own
    [InlineData(UserType.ClientUser, 1)]  // Can only access Own
    public void GetAllAvailablePermissions_ShouldReturnCorrectScopeCount(UserType userType, int expectedScopeCount)
    {
        var permissionsByScope = _authService.GetAllAvailablePermissions(userType);

        Assert.Equal(expectedScopeCount, permissionsByScope.Count);
    }

    [Theory]
    [InlineData("platform:admin", AuthorizationScope.Platform, true)]
    [InlineData("platform:admin", AuthorizationScope.Tenant, false)]
    [InlineData("tenant:read", AuthorizationScope.Tenant, true)]
    [InlineData("client:read", AuthorizationScope.Own, true)]
    public void PermissionRequiresScope_ShouldReturnCorrectResult(string permission, AuthorizationScope scope, bool expectedResult)
    {
        var result = _authService.PermissionRequiresScope(permission, scope);

        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void Authorize_WithNullContext_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _authService.Authorize(null!, "test:permission"));
    }

    [Fact]
    public void Authorize_WithNullPermission_ShouldThrowArgumentNullException()
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);
        Assert.Throws<ArgumentNullException>(() => _authService.Authorize(context, null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Authorize_WithEmptyPermission_ShouldThrowArgumentException(string permission)
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);
        Assert.Throws<ArgumentException>(() => _authService.Authorize(context, permission));
    }

    [Fact]
    public void AuthorizeTenantAccess_WithNullContext_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _authService.AuthorizeTenantAccess(null!, "tenant1"));
    }

    [Fact]
    public void AuthorizeTenantAccess_WithNullTenantId_ShouldThrowArgumentNullException()
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);
        Assert.Throws<ArgumentNullException>(() => _authService.AuthorizeTenantAccess(context, null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void AuthorizeTenantAccess_WithEmptyTenantId_ShouldThrowArgumentException(string tenantId)
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);
        Assert.Throws<ArgumentException>(() => _authService.AuthorizeTenantAccess(context, tenantId));
    }

    [Fact]
    public void AuthorizeClientAccess_WithNullContext_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _authService.AuthorizeClientAccess(null!, "client1"));
    }

    [Fact]
    public void AuthorizeClientAccess_WithNullClientId_ShouldThrowArgumentNullException()
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);
        Assert.Throws<ArgumentNullException>(() => _authService.AuthorizeClientAccess(context, null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void AuthorizeClientAccess_WithEmptyClientId_ShouldThrowArgumentException(string clientId)
    {
        var context = new AuthorizationContext("user1", "tenant1", "client1", UserType.SuperAdmin, []);
        Assert.Throws<ArgumentException>(() => _authService.AuthorizeClientAccess(context, clientId));
    }

    [Fact]
    public void PermissionRequiresScope_WithNullPermission_ShouldThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _authService.PermissionRequiresScope(null!, AuthorizationScope.Own));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void PermissionRequiresScope_WithEmptyPermission_ShouldThrowArgumentException(string permission)
    {
        Assert.Throws<ArgumentException>(() => _authService.PermissionRequiresScope(permission, AuthorizationScope.Own));
    }

    private static List<string> GetPermissionsForUserType(UserType userType)
    {
        return userType switch
        {
            UserType.SuperAdmin => ["platform:admin", "tenant:read", "client:read"],
            UserType.TenantAdmin => ["tenant:read", "client:read"],
            UserType.ClientUser => ["client:read"],
            _ => []
        };
    }
}