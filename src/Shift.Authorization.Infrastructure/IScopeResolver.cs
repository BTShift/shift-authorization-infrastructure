namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Interface for resolving authorization scopes based on permissions and user context
/// </summary>
public interface IScopeResolver
{
    /// <summary>
    /// Gets the required authorization scope for a specific permission
    /// </summary>
    /// <param name="permission">The permission to check</param>
    /// <returns>The required authorization scope</returns>
    AuthorizationScope GetRequiredScope(string permission);

    /// <summary>
    /// Gets all permissions that require the specified scope
    /// </summary>
    /// <param name="scope">The authorization scope</param>
    /// <returns>List of permissions requiring the scope</returns>
    IReadOnlyList<string> GetPermissionsForScope(AuthorizationScope scope);

    /// <summary>
    /// Checks if a user type can operate at the specified scope
    /// </summary>
    /// <param name="userType">The user type</param>
    /// <param name="scope">The required scope</param>
    /// <returns>True if the user type can operate at the scope</returns>
    bool CanOperateAtScope(UserType userType, AuthorizationScope scope);

    /// <summary>
    /// Gets the maximum scope a user type can operate at
    /// </summary>
    /// <param name="userType">The user type</param>
    /// <returns>The maximum authorization scope for the user type</returns>
    AuthorizationScope GetMaximumScope(UserType userType);
}