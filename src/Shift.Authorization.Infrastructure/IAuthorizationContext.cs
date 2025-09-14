namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the contract for authorization context that provides scoped authorization information
/// </summary>
public interface IAuthorizationContext
{
    /// <summary>
    /// Gets the user identifier
    /// </summary>
    string UserId { get; }

    /// <summary>
    /// Gets the tenant identifier for multi-tenant context
    /// </summary>
    string TenantId { get; }

    /// <summary>
    /// Gets the authorization scopes available to the current user
    /// </summary>
    IEnumerable<string> Scopes { get; }

    /// <summary>
    /// Checks if the current context has the specified scope
    /// </summary>
    /// <param name="scope">The scope to check</param>
    /// <returns>True if the scope is available, false otherwise</returns>
    bool HasScope(string scope);
}