namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Configuration class that maps permissions to their required authorization scope and allowed user types
/// </summary>
public class PermissionScopeMapping
{
    /// <summary>
    /// Gets or sets the permission name
    /// </summary>
    public string Permission { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the required authorization scope for this permission
    /// </summary>
    public AuthorizationScope RequiredScope { get; set; }

    /// <summary>
    /// Gets or sets the list of user types that are allowed to use this permission
    /// </summary>
    public List<string> AllowedUserTypes { get; set; } = new();

    /// <summary>
    /// Gets or sets an optional description of what this permission allows
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Checks if the specified user type is allowed to use this permission
    /// </summary>
    /// <param name="userType">The user type to check</param>
    /// <returns>True if the user type is allowed</returns>
    public bool IsUserTypeAllowed(UserType userType)
    {
        var userTypeString = userType.ToString();
        return AllowedUserTypes.Contains(userTypeString, StringComparer.OrdinalIgnoreCase) ||
               AllowedUserTypes.Contains(userTypeString.ToLowerInvariant()) ||
               AllowedUserTypes.Contains(ConvertUserTypeToString(userType));
    }

    private static string ConvertUserTypeToString(UserType userType)
    {
        return userType switch
        {
            UserType.SuperAdmin => "super_admin",
            UserType.TenantAdmin => "tenant_admin",
            UserType.ClientUser => "client_user",
            _ => userType.ToString().ToLowerInvariant()
        };
    }
}