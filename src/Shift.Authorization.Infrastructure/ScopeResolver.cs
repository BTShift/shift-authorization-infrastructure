namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Implementation of IScopeResolver that provides scope determination based on permission mappings
/// </summary>
public class ScopeResolver : IScopeResolver
{
    private readonly Dictionary<string, PermissionScopeMapping> _permissionMappings;
    private readonly Dictionary<AuthorizationScope, IReadOnlyList<string>> _scopeToPermissions;

    /// <summary>
    /// Initializes a new instance of the ScopeResolver class with permission mappings
    /// </summary>
    /// <param name="permissionMappings">The permission to scope mappings</param>
    public ScopeResolver(IEnumerable<PermissionScopeMapping> permissionMappings)
    {
        ArgumentNullException.ThrowIfNull(permissionMappings);

        // Handle duplicate permissions by taking the last one (similar to Dictionary behavior)
        _permissionMappings = new Dictionary<string, PermissionScopeMapping>(StringComparer.OrdinalIgnoreCase);
        foreach (var mapping in permissionMappings)
        {
            _permissionMappings[mapping.Permission] = mapping;
        }

        // Create reverse mapping for scope to permissions lookup
        _scopeToPermissions = _permissionMappings
            .GroupBy(kvp => kvp.Value.RequiredScope)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<string>)group.Select(kvp => kvp.Key).ToList());
    }

    /// <summary>
    /// Initializes a new instance of the ScopeResolver class with default permission mappings
    /// </summary>
    public ScopeResolver() : this(GetDefaultPermissionMappings())
    {
    }

    /// <inheritdoc/>
    public AuthorizationScope GetRequiredScope(string permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        return _permissionMappings.TryGetValue(permission, out var mapping)
            ? mapping.RequiredScope
            : AuthorizationScope.Own; // Default to most restrictive scope
    }

    /// <inheritdoc/>
    public IReadOnlyList<string> GetPermissionsForScope(AuthorizationScope scope)
    {
        return _scopeToPermissions.TryGetValue(scope, out var permissions)
            ? permissions
            : Array.Empty<string>();
    }

    /// <inheritdoc/>
    public bool CanOperateAtScope(UserType userType, AuthorizationScope scope)
    {
        return userType switch
        {
            UserType.SuperAdmin => true, // SuperAdmin can operate at any scope
            UserType.TenantAdmin => scope is AuthorizationScope.Tenant or AuthorizationScope.Own,
            UserType.ClientUser => scope is AuthorizationScope.Own,
            _ => false
        };
    }

    /// <inheritdoc/>
    public AuthorizationScope GetMaximumScope(UserType userType)
    {
        return userType switch
        {
            UserType.SuperAdmin => AuthorizationScope.Platform,
            UserType.TenantAdmin => AuthorizationScope.Tenant,
            UserType.ClientUser => AuthorizationScope.Own,
            _ => AuthorizationScope.Own
        };
    }

    /// <summary>
    /// Gets the permission mapping for a specific permission
    /// </summary>
    /// <param name="permission">The permission to get mapping for</param>
    /// <returns>The permission mapping if found, null otherwise</returns>
    public PermissionScopeMapping? GetPermissionMapping(string permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        return _permissionMappings.TryGetValue(permission, out var mapping) ? mapping : null;
    }

    /// <summary>
    /// Checks if a user type is allowed to use a specific permission
    /// </summary>
    /// <param name="permission">The permission to check</param>
    /// <param name="userType">The user type to check</param>
    /// <returns>True if the user type is allowed to use the permission</returns>
    public bool IsPermissionAllowedForUserType(string permission, UserType userType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        var mapping = GetPermissionMapping(permission);
        return mapping?.IsUserTypeAllowed(userType) ?? false;
    }

    /// <summary>
    /// Gets the default permission mappings for the system
    /// </summary>
    private static List<PermissionScopeMapping> GetDefaultPermissionMappings()
    {
        return new List<PermissionScopeMapping>
        {
            // Platform-level permissions
            new()
            {
                Permission = "platform:admin",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"],
                Description = "Full platform administration access"
            },
            new()
            {
                Permission = "platform:read",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"],
                Description = "Read-only platform access"
            },
            new()
            {
                Permission = "platform:write",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"],
                Description = "Write access to platform resources"
            },
            new()
            {
                Permission = "users:manage",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"],
                Description = "Manage users across all tenants"
            },
            new()
            {
                Permission = "tenants:manage",
                RequiredScope = AuthorizationScope.Platform,
                AllowedUserTypes = ["SuperAdmin"],
                Description = "Manage tenant accounts and settings"
            },

            // Tenant-level permissions
            new()
            {
                Permission = "tenant:admin",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
                Description = "Tenant administration access"
            },
            new()
            {
                Permission = "tenant:read",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
                Description = "Read tenant data and settings"
            },
            new()
            {
                Permission = "tenant:write",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
                Description = "Write to tenant resources"
            },
            new()
            {
                Permission = "clients:manage",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
                Description = "Manage clients within tenant"
            },
            new()
            {
                Permission = "reports:tenant",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
                Description = "Generate tenant-level reports"
            },
            new()
            {
                Permission = "users:tenant",
                RequiredScope = AuthorizationScope.Tenant,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
                Description = "Manage users within tenant"
            },

            // Client-level permissions (Own scope)
            new()
            {
                Permission = "client:read",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Read client data"
            },
            new()
            {
                Permission = "client:write",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Write to client resources"
            },
            new()
            {
                Permission = "documents:own",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Manage own documents"
            },
            new()
            {
                Permission = "reports:own",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Generate personal reports"
            },
            new()
            {
                Permission = "profile:manage",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Manage personal profile"
            },

            // Financial/Accounting permissions
            new()
            {
                Permission = "accounting:read",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Read accounting data"
            },
            new()
            {
                Permission = "accounting:write",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Write accounting data"
            },
            new()
            {
                Permission = "invoices:manage",
                RequiredScope = AuthorizationScope.Own,
                AllowedUserTypes = ["SuperAdmin", "TenantAdmin", "ClientUser"],
                Description = "Manage invoices"
            }
        };
    }
}