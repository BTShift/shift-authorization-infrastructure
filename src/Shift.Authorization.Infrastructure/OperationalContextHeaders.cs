namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the HTTP header names used for operational context
/// </summary>
public static class OperationalContextHeaders
{
    /// <summary>
    /// Header for specifying the target tenant ID for cross-tenant operations
    /// </summary>
    public const string TenantId = "X-Operation-Tenant-Id";

    /// <summary>
    /// Header for specifying the target client ID for cross-client operations
    /// </summary>
    public const string ClientId = "X-Operation-Client-Id";
}