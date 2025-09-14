namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Represents the operational context for cross-tenant/client operations
/// </summary>
public class OperationalContext
{
    /// <summary>
    /// Gets or sets the target tenant ID for cross-tenant operations (SuperAdmin only)
    /// </summary>
    public string? OperationTenantId { get; set; }

    /// <summary>
    /// Gets or sets the target client ID for cross-client operations (SuperAdmin, TenantAdmin)
    /// </summary>
    public string? OperationClientId { get; set; }

    /// <summary>
    /// Gets or sets whether this is an operational context (headers were provided)
    /// </summary>
    public bool IsOperationalContext { get; set; }

    /// <summary>
    /// Gets the effective tenant ID for the current operation
    /// Returns OperationTenantId if set, otherwise falls back to the original TenantId
    /// </summary>
    /// <param name="originalTenantId">The original tenant ID from the auth context</param>
    /// <returns>The effective tenant ID for the operation</returns>
    public string? GetEffectiveTenantId(string? originalTenantId)
    {
        return OperationTenantId ?? originalTenantId;
    }

    /// <summary>
    /// Gets the effective client ID for the current operation
    /// Returns OperationClientId if set, otherwise falls back to the original ClientId
    /// </summary>
    /// <param name="originalClientId">The original client ID from the auth context</param>
    /// <returns>The effective client ID for the operation</returns>
    public string? GetEffectiveClientId(string? originalClientId)
    {
        return OperationClientId ?? originalClientId;
    }
}