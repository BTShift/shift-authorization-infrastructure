using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Implementation of authorization context that provides scoped authorization information
/// by parsing JWT claims and providing permission validation logic
/// </summary>
public class AuthorizationContext : IAuthorizationContext
{
    private readonly List<string> _permissions;
    private readonly Dictionary<string, AuthorizationScope> _permissionScopes;

    /// <summary>
    /// Initializes a new instance of the AuthorizationContext class
    /// </summary>
    /// <param name="claimsPrincipal">The claims principal containing user information</param>
    public AuthorizationContext(ClaimsPrincipal claimsPrincipal)
    {
        ArgumentNullException.ThrowIfNull(claimsPrincipal);

        var claims = claimsPrincipal.Claims.ToList();

        // Parse basic user information
        UserId = GetClaimValue(claims, JwtRegisteredClaimNames.Sub);
        TenantId = GetClaimValue(claims, "tenant_id");
        ClientId = GetClaimValue(claims, "client_id");

        // Parse user type
        var userTypeString = GetClaimValue(claims, "user_type");
        UserType = ParseUserType(userTypeString);

        // Parse permissions
        _permissions = GetPermissionsFromClaims(claims);

        // Initialize permission scope mappings based on user type
        _permissionScopes = InitializePermissionScopes();
    }

    /// <summary>
    /// Initializes a new instance of the AuthorizationContext class for testing
    /// </summary>
    /// <param name="userId">User identifier</param>
    /// <param name="tenantId">Tenant identifier</param>
    /// <param name="clientId">Client identifier</param>
    /// <param name="userType">User type</param>
    /// <param name="permissions">List of permissions</param>
    public AuthorizationContext(string? userId, string? tenantId, string? clientId, UserType userType, List<string> permissions)
    {
        UserId = userId;
        TenantId = tenantId;
        ClientId = clientId;
        UserType = userType;
        _permissions = permissions ?? new List<string>();
        _permissionScopes = InitializePermissionScopes();
    }

    /// <inheritdoc/>
    public string? UserId { get; }

    /// <inheritdoc/>
    public string? TenantId { get; }

    /// <inheritdoc/>
    public string? ClientId { get; }

    /// <inheritdoc/>
    public UserType UserType { get; }

    /// <inheritdoc/>
    public List<string> Permissions => new(_permissions);

    /// <inheritdoc/>
    public AuthorizationScope GetRequiredScope(string permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        return _permissionScopes.TryGetValue(permission, out var scope) ? scope : AuthorizationScope.Own;
    }

    /// <inheritdoc/>
    public bool HasPermission(string permission, AuthorizationScope scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        // Check if user has the permission
        if (!_permissions.Contains(permission))
            return false;

        // Check if user type allows the required scope
        return CanOperateAtScope(scope);
    }

    /// <inheritdoc/>
    public bool CanAccessTenant(string tenantId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);

        return UserType switch
        {
            UserType.SuperAdmin => true, // SuperAdmin can access any tenant
            UserType.TenantAdmin => string.Equals(TenantId, tenantId, StringComparison.OrdinalIgnoreCase),
            UserType.ClientUser => string.Equals(TenantId, tenantId, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    /// <inheritdoc/>
    public bool CanAccessClient(string clientId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        return UserType switch
        {
            UserType.SuperAdmin => true, // SuperAdmin can access any client
            UserType.TenantAdmin => CanAccessClientAsTenantAdmin(clientId),
            UserType.ClientUser => string.Equals(ClientId, clientId, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static string? GetClaimValue(IEnumerable<Claim> claims, string claimType)
    {
        return claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }

    private static UserType ParseUserType(string? userTypeString)
    {
        if (string.IsNullOrWhiteSpace(userTypeString))
            return UserType.ClientUser; // Default to most restrictive

        return userTypeString.ToLowerInvariant() switch
        {
            "superadmin" or "super_admin" => UserType.SuperAdmin,
            "tenantadmin" or "tenant_admin" => UserType.TenantAdmin,
            "clientuser" or "client_user" => UserType.ClientUser,
            _ => UserType.ClientUser // Default to most restrictive
        };
    }

    private static List<string> GetPermissionsFromClaims(IEnumerable<Claim> claims)
    {
        var permissions = new List<string>();

        // Get permissions from individual permission claims
        permissions.AddRange(claims
            .Where(c => c.Type == "permission")
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v)));

        // Get permissions from scope claim (space-separated)
        var scopeClaim = claims.FirstOrDefault(c => c.Type == "scope")?.Value;
        if (!string.IsNullOrWhiteSpace(scopeClaim))
        {
            var scopePermissions = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            permissions.AddRange(scopePermissions);
        }

        return permissions.Distinct().ToList();
    }

    private static Dictionary<string, AuthorizationScope> InitializePermissionScopes()
    {
        // This would typically be loaded from configuration or a database
        // For now, we'll use some common permission patterns
        return new Dictionary<string, AuthorizationScope>(StringComparer.OrdinalIgnoreCase)
        {
            // Platform-level permissions
            ["platform:admin"] = AuthorizationScope.Platform,
            ["platform:read"] = AuthorizationScope.Platform,
            ["platform:write"] = AuthorizationScope.Platform,
            ["users:manage"] = AuthorizationScope.Platform,
            ["tenants:manage"] = AuthorizationScope.Platform,

            // Tenant-level permissions
            ["tenant:admin"] = AuthorizationScope.Tenant,
            ["tenant:read"] = AuthorizationScope.Tenant,
            ["tenant:write"] = AuthorizationScope.Tenant,
            ["clients:manage"] = AuthorizationScope.Tenant,
            ["reports:tenant"] = AuthorizationScope.Tenant,

            // Client-level permissions (Own scope)
            ["client:read"] = AuthorizationScope.Own,
            ["client:write"] = AuthorizationScope.Own,
            ["documents:own"] = AuthorizationScope.Own,
            ["reports:own"] = AuthorizationScope.Own,
        };
    }

    private bool CanOperateAtScope(AuthorizationScope requiredScope)
    {
        return UserType switch
        {
            UserType.SuperAdmin => true, // SuperAdmin can operate at any scope
            UserType.TenantAdmin => requiredScope is AuthorizationScope.Tenant or AuthorizationScope.Own,
            UserType.ClientUser => requiredScope is AuthorizationScope.Own,
            _ => false
        };
    }

    private bool CanAccessClientAsTenantAdmin(string clientId)
    {
        // For TenantAdmin, they can access clients within their tenant
        // This would typically require checking if the client belongs to the same tenant
        // For now, we'll allow access if they have a tenant ID (simplified logic)
        return !string.IsNullOrWhiteSpace(TenantId);
    }
}