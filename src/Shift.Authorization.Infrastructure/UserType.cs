namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the types of users in the system hierarchy
/// </summary>
public enum UserType
{
    /// <summary>
    /// Platform-level super administrator with full system access
    /// </summary>
    SuperAdmin,

    /// <summary>
    /// Tenant administrator with access to tenant-level operations
    /// </summary>
    TenantAdmin,

    /// <summary>
    /// Client user with limited access to own resources
    /// </summary>
    ClientUser
}