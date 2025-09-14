namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the authorization scopes for different levels of access
/// </summary>
public enum AuthorizationScope
{
    /// <summary>
    /// Platform-level access for super administrators
    /// </summary>
    Platform,

    /// <summary>
    /// Tenant-level access for tenant administrators
    /// </summary>
    Tenant,

    /// <summary>
    /// Own resource access for client users
    /// </summary>
    Own
}