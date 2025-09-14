namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the contract for authorization context that provides scoped authorization information
/// including tenant, client, user, and permission data for the 3-layer authorization model
/// </summary>
public interface IAuthorizationContext
{
    /// <summary>
    /// Gets the user identifier
    /// </summary>
    string? UserId { get; }

    /// <summary>
    /// Gets the tenant identifier for multi-tenant context
    /// </summary>
    string? TenantId { get; }

    /// <summary>
    /// Gets the client identifier
    /// </summary>
    string? ClientId { get; }

    /// <summary>
    /// Gets the type of user (SuperAdmin, TenantAdmin, ClientUser)
    /// </summary>
    UserType UserType { get; }

    /// <summary>
    /// Gets the list of permissions available to the current user
    /// </summary>
    List<string> Permissions { get; }

    /// <summary>
    /// Gets the required authorization scope for a specific permission
    /// </summary>
    /// <param name="permission">The permission to check</param>
    /// <returns>The required authorization scope</returns>
    AuthorizationScope GetRequiredScope(string permission);

    /// <summary>
    /// Checks if the current context has the specified permission with the required scope
    /// </summary>
    /// <param name="permission">The permission to check</param>
    /// <param name="scope">The required scope</param>
    /// <returns>True if the user has the permission with the required scope</returns>
    bool HasPermission(string permission, AuthorizationScope scope);

    /// <summary>
    /// Checks if the current user can access the specified tenant
    /// </summary>
    /// <param name="tenantId">The tenant identifier to check access for</param>
    /// <returns>True if the user can access the tenant</returns>
    bool CanAccessTenant(string tenantId);

    /// <summary>
    /// Checks if the current user can access the specified client
    /// </summary>
    /// <param name="clientId">The client identifier to check access for</param>
    /// <returns>True if the user can access the client</returns>
    bool CanAccessClient(string clientId);
}