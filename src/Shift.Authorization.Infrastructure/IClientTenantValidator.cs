namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the contract for validating client-tenant relationships
/// </summary>
public interface IClientTenantValidator
{
    /// <summary>
    /// Validates whether a client belongs to a specific tenant
    /// </summary>
    /// <param name="clientId">The client identifier to validate</param>
    /// <param name="tenantId">The tenant identifier to check against</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if the client belongs to the tenant, false otherwise</returns>
    Task<bool> ValidateClientBelongsToTenantAsync(string clientId, string tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a tenant exists in the system
    /// </summary>
    /// <param name="tenantId">The tenant identifier to check</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if the tenant exists, false otherwise</returns>
    Task<bool> TenantExistsAsync(string tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a client exists in the system
    /// </summary>
    /// <param name="clientId">The client identifier to check</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if the client exists, false otherwise</returns>
    Task<bool> ClientExistsAsync(string clientId, CancellationToken cancellationToken = default);
}