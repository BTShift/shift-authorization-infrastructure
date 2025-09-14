namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Service that provides comprehensive authorization decisions based on the 3-layer authorization scope system
/// </summary>
public class ScopeBasedAuthorizationService
{
    private readonly IScopeResolver _scopeResolver;

    /// <summary>
    /// Initializes a new instance of the ScopeBasedAuthorizationService class
    /// </summary>
    /// <param name="scopeResolver">The scope resolver to use for permission mapping</param>
    public ScopeBasedAuthorizationService(IScopeResolver scopeResolver)
    {
        _scopeResolver = scopeResolver ?? throw new ArgumentNullException(nameof(scopeResolver));
    }

    /// <summary>
    /// Authorizes a permission request against the provided authorization context
    /// </summary>
    /// <param name="context">The authorization context</param>
    /// <param name="permission">The permission being requested</param>
    /// <returns>True if the request is authorized</returns>
    public bool Authorize(IAuthorizationContext context, string permission)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        // Check if user has the permission
        if (!context.Permissions.Contains(permission))
            return false;

        // Get the required scope for the permission
        var requiredScope = _scopeResolver.GetRequiredScope(permission);

        // Check if the user type can operate at the required scope
        if (!_scopeResolver.CanOperateAtScope(context.UserType, requiredScope))
            return false;

        // Check if user type is allowed for this specific permission
        if (_scopeResolver is ScopeResolver scopeResolver)
        {
            if (!scopeResolver.IsPermissionAllowedForUserType(permission, context.UserType))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Authorizes a permission request with explicit scope requirement
    /// </summary>
    /// <param name="context">The authorization context</param>
    /// <param name="permission">The permission being requested</param>
    /// <param name="requiredScope">The explicitly required scope</param>
    /// <returns>True if the request is authorized</returns>
    public bool Authorize(IAuthorizationContext context, string permission, AuthorizationScope requiredScope)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        // Check if user has the permission
        if (!context.Permissions.Contains(permission))
            return false;

        // Use the explicitly provided scope instead of resolving it
        return _scopeResolver.CanOperateAtScope(context.UserType, requiredScope);
    }

    /// <summary>
    /// Authorizes tenant access for the current context
    /// </summary>
    /// <param name="context">The authorization context</param>
    /// <param name="targetTenantId">The tenant ID to access</param>
    /// <returns>True if tenant access is authorized</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Method is part of service interface and may use instance state in future")]
    public bool AuthorizeTenantAccess(IAuthorizationContext context, string targetTenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetTenantId);

        return context.CanAccessTenant(targetTenantId);
    }

    /// <summary>
    /// Authorizes client access for the current context
    /// </summary>
    /// <param name="context">The authorization context</param>
    /// <param name="targetClientId">The client ID to access</param>
    /// <returns>True if client access is authorized</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Method is part of service interface and may use instance state in future")]
    public bool AuthorizeClientAccess(IAuthorizationContext context, string targetClientId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetClientId);

        return context.CanAccessClient(targetClientId);
    }

    /// <summary>
    /// Authorizes resource access with tenant and client context
    /// </summary>
    /// <param name="context">The authorization context</param>
    /// <param name="permission">The permission being requested</param>
    /// <param name="resourceTenantId">The tenant ID of the resource</param>
    /// <param name="resourceClientId">The client ID of the resource (optional)</param>
    /// <returns>True if resource access is authorized</returns>
    public bool AuthorizeResourceAccess(IAuthorizationContext context, string permission,
        string resourceTenantId, string? resourceClientId = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceTenantId);

        // First check if user has the permission
        if (!Authorize(context, permission))
            return false;

        // Check tenant access
        if (!AuthorizeTenantAccess(context, resourceTenantId))
            return false;

        // If client ID is provided, check client access
        if (!string.IsNullOrWhiteSpace(resourceClientId))
        {
            return AuthorizeClientAccess(context, resourceClientId);
        }

        return true;
    }

    /// <summary>
    /// Gets all permissions available to a user type at a specific scope
    /// </summary>
    /// <param name="userType">The user type</param>
    /// <param name="scope">The authorization scope</param>
    /// <returns>List of available permissions</returns>
    public IReadOnlyList<string> GetAvailablePermissions(UserType userType, AuthorizationScope scope)
    {
        var scopePermissions = _scopeResolver.GetPermissionsForScope(scope);

        if (_scopeResolver is ScopeResolver scopeResolver)
        {
            return scopePermissions
                .Where(permission => scopeResolver.IsPermissionAllowedForUserType(permission, userType))
                .ToList();
        }

        return scopePermissions;
    }

    /// <summary>
    /// Gets all permissions available to a user type across all scopes they can access
    /// </summary>
    /// <param name="userType">The user type</param>
    /// <returns>Dictionary mapping scopes to available permissions</returns>
    public IReadOnlyDictionary<AuthorizationScope, IReadOnlyList<string>> GetAllAvailablePermissions(UserType userType)
    {
        var result = new Dictionary<AuthorizationScope, IReadOnlyList<string>>();
        var maxScope = _scopeResolver.GetMaximumScope(userType);

        // Add permissions for all scopes the user can operate at
        foreach (AuthorizationScope scope in Enum.GetValues<AuthorizationScope>())
        {
            if (_scopeResolver.CanOperateAtScope(userType, scope))
            {
                result[scope] = GetAvailablePermissions(userType, scope);
            }
        }

        return result;
    }

    /// <summary>
    /// Checks if a permission requires a specific scope level
    /// </summary>
    /// <param name="permission">The permission to check</param>
    /// <param name="scope">The scope to compare against</param>
    /// <returns>True if the permission requires the specified scope</returns>
    public bool PermissionRequiresScope(string permission, AuthorizationScope scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        return _scopeResolver.GetRequiredScope(permission) == scope;
    }
}