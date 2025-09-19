using System.Security.Claims;
using System.Security.Principal;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security;
using DevExpress.Persistent.BaseImpl.EF.PermissionPolicy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xaf.Blazor.KeycloakAuth.Configuration;

namespace Xaf.Blazor.KeycloakAuth.Authentication;

/// <summary>
/// Generic Keycloak authentication provider for XAF applications.
/// Supports automatic user creation, property mapping, and role assignment.
/// </summary>
/// <typeparam name="TUser">The user type that implements ISecurityUserWithLoginInfo</typeparam>
/// <typeparam name="TUserLoginInfo">The user login info type that implements ISecurityUserLoginInfo</typeparam>
/// <typeparam name="TRole">The role type that implements ISecurityRole</typeparam>
public class KeycloakAuthenticationProvider<TUser, TUserLoginInfo, TRole> : IAuthenticationProviderV2
    where TUser : class, ISecurityUserWithLoginInfo, new()
    where TUserLoginInfo : class, ISecurityUserLoginInfo
    where TRole : class, ISecurityRole
{
    private readonly IPrincipalProvider _principalProvider;
    private readonly ILogger<KeycloakAuthenticationProvider<TUser, TUserLoginInfo, TRole>> _logger;
    private readonly XafKeycloakOptions _options;

    /// <summary>
    /// Gets the logger instance for derived classes
    /// </summary>
    protected ILogger<KeycloakAuthenticationProvider<TUser, TUserLoginInfo, TRole>> Logger => _logger;

    /// <summary>
    /// Initializes a new instance of the KeycloakAuthenticationProvider
    /// </summary>
    /// <param name="principalProvider">The principal provider for accessing current user</param>
    /// <param name="logger">The logger instance</param>
    /// <param name="options">The Keycloak configuration options</param>
    public KeycloakAuthenticationProvider(
        IPrincipalProvider principalProvider,
        ILogger<KeycloakAuthenticationProvider<TUser, TUserLoginInfo, TRole>> logger,
        IOptions<XafKeycloakOptions> options)
    {
        _principalProvider = principalProvider;
        _logger = logger;
        _options = options.Value;
    }

    /// <summary>
    /// Authenticates the user based on Keycloak claims
    /// </summary>
    public object? Authenticate(IObjectSpace objectSpace)
    {
        if (!CanHandlePrincipal(_principalProvider.User))
        {
            return null;
        }

        var claimsPrincipal = (ClaimsPrincipal)_principalProvider.User;
        
        try
        {
            // Get user identification claims from Keycloak
            var userIdClaim = claimsPrincipal.FindFirst("sub") ?? 
                             claimsPrincipal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
            
            if (userIdClaim == null)
            {
                _logger.LogError("Unable to find user identifier claim ('sub' or NameIdentifier) in Keycloak token");
                throw new InvalidOperationException("Unknown user id - missing 'sub' or NameIdentifier claim");
            }

            var providerUserKey = userIdClaim.Value;
            var loginProviderName = claimsPrincipal.Identity?.AuthenticationType ?? _options.Authentication.SchemeName;
            
            // Try to get username from various claims
            var userName = GetUserNameFromClaims(claimsPrincipal);
            
            if (string.IsNullOrEmpty(userName))
            {
                _logger.LogError("Unable to determine username from Keycloak claims");
                throw new InvalidOperationException("Unable to determine username from Keycloak claims");
            }

            _logger.LogInformation("Authenticating user: {UserName} with provider: {Provider}", userName, loginProviderName);

            // Look for existing user login info
            var userLoginInfo = FindUserLoginInfo(objectSpace, loginProviderName, providerUserKey);
            if (userLoginInfo != null)
            {
                _logger.LogInformation("Found existing user login info for: {UserName}", userName);
                return userLoginInfo.User;
            }

            // Auto-create user if enabled and not found
            if (_options.UserMapping.AutoCreateUsers)
            {
                _logger.LogInformation("Creating new user: {UserName}", userName);
                return CreateApplicationUser(objectSpace, claimsPrincipal, userName, loginProviderName, providerUserKey);
            }

            _logger.LogWarning("User {UserName} not found and auto-creation is disabled", userName);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Keycloak authentication for user");
            throw;
        }
    }

    /// <summary>
    /// Determines if this provider can handle the current principal
    /// </summary>
    /// <summary>
    /// Determines if this authentication provider can handle the current principal
    /// </summary>
    /// <param name="user">The current principal</param>
    /// <returns>True if this provider can handle the principal</returns>
    protected virtual bool CanHandlePrincipal(IPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true)
            return false;

        var authType = user.Identity.AuthenticationType;
        
        // Exclude XAF internal authentication types
        if (authType == SecurityDefaults.Issuer ||
            authType == SecurityDefaults.PasswordAuthentication ||
            authType == SecurityDefaults.WindowsAuthentication ||
            user is WindowsPrincipal)
        {
            return false;
        }

        // Check for Keycloak authentication schemes
        var isKeycloakAuth = authType == _options.Authentication.SchemeName ||
                            authType == "OpenIdConnect" ||
                            authType == "Keycloak";

        if (isKeycloakAuth)
        {
            _logger.LogDebug("Handling authentication for scheme: {AuthType}", authType);
            return true;
        }

        // Check for Keycloak-specific claims as fallback
        if (user is ClaimsPrincipal claimsPrincipal && HasKeycloakClaims(claimsPrincipal))
        {
            _logger.LogDebug("Detected Keycloak claims in principal with auth type: {AuthType}", authType);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Checks if the principal has Keycloak-specific claims
    /// </summary>
    /// <summary>
    /// Checks if the claims principal has Keycloak-specific claims
    /// </summary>
    /// <param name="principal">The claims principal to check</param>
    /// <returns>True if Keycloak claims are present</returns>
    protected virtual bool HasKeycloakClaims(ClaimsPrincipal principal)
    {
        var keycloakClaims = new[] { "iss", "aud", "typ", "azp", "session_state", "preferred_username" };
        return keycloakClaims.Any(claimType => principal.Claims.Any(c => c.Type == claimType));
    }

    /// <summary>
    /// Extracts username from various Keycloak claims
    /// </summary>
    /// <summary>
    /// Extracts the username from Keycloak claims
    /// </summary>
    /// <param name="claimsPrincipal">The claims principal containing Keycloak claims</param>
    /// <returns>The extracted username or null if not found</returns>
    protected virtual string? GetUserNameFromClaims(ClaimsPrincipal claimsPrincipal)
    {
        // Try preferred_username first (Keycloak standard)
        var userName = claimsPrincipal.FindFirst("preferred_username")?.Value;
        
        // Fallback to standard claims
        userName ??= claimsPrincipal.Identity?.Name;
        userName ??= claimsPrincipal.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
        userName ??= claimsPrincipal.FindFirst("name")?.Value;
        
        return userName;
    }

    /// <summary>
    /// Creates a new application user from Keycloak claims
    /// </summary>
    /// <summary>
    /// Creates a new application user from Keycloak claims
    /// </summary>
    /// <param name="objectSpace">The object space for database operations</param>
    /// <param name="claimsPrincipal">The claims principal containing user information</param>
    /// <param name="userName">The username for the new user</param>
    /// <param name="loginProviderName">The login provider name (typically "Keycloak")</param>
    /// <param name="providerUserKey">The unique provider user key</param>
    /// <returns>The created user object</returns>
    protected virtual object CreateApplicationUser(IObjectSpace objectSpace, ClaimsPrincipal claimsPrincipal, 
        string userName, string loginProviderName, string providerUserKey)
    {
        // Check if user already exists by username
        var existingUser = objectSpace.GetObjects<TUser>().FirstOrDefault(u => 
            GetUserNameProperty(u)?.Equals(userName, StringComparison.OrdinalIgnoreCase) == true);
            
        if (existingUser != null)
        {
            var error = $"The username ('{userName}') was already registered within the system";
            _logger.LogError(error);
            throw new ArgumentException(error);
        }

        var user = objectSpace.CreateObject<TUser>();
        
        // Set username
        SetUserNameProperty(user, userName);
        
        // Map additional properties from claims
        MapUserPropertiesFromClaims(user, claimsPrincipal);
        
        // Set random password (required by XAF)
        if (user is PermissionPolicyUser policyUser)
        {
            policyUser.SetPassword(Guid.NewGuid().ToString());
        }
        
        // Assign roles
        AssignUserRoles(objectSpace, user, claimsPrincipal);
        
        // Create user login info for external authentication
        user.CreateUserLoginInfo(loginProviderName, providerUserKey);
        
        // Apply custom user creation logic if provided
        if (_options.UserMapping.CustomUserCreation != null)
        {
            var claimsDict = claimsPrincipal.Claims.ToDictionary(c => c.Type, c => (object)c.Value);
            _options.UserMapping.CustomUserCreation(user, claimsDict);
        }
        
        objectSpace.CommitChanges();
        
        _logger.LogInformation("Successfully created user: {UserName} with provider: {Provider}", userName, loginProviderName);
        
        return user;
    }

    /// <summary>
    /// Maps user properties from Keycloak claims based on configuration
    /// </summary>
    /// <summary>
    /// Maps properties from Keycloak claims to the user object
    /// </summary>
    /// <param name="user">The user object to update</param>
    /// <param name="claimsPrincipal">The claims principal containing claim data</param>
    protected virtual void MapUserPropertiesFromClaims(TUser user, ClaimsPrincipal claimsPrincipal)
    {
        foreach (var mapping in _options.UserMapping.PropertyMappings)
        {
            var propertyName = mapping.Key;
            var claimName = mapping.Value;
            
            var claimValue = claimsPrincipal.FindFirst(claimName)?.Value ?? 
                           claimsPrincipal.FindFirst(ClaimTypes.GetClaimTypeFromName(claimName))?.Value;
            
            if (!string.IsNullOrEmpty(claimValue))
            {
                SetPropertyIfExists(user, propertyName, claimValue);
            }
        }
    }

    /// <summary>
    /// Assigns roles to the user based on configuration and claims
    /// </summary>
    /// <summary>
    /// Assigns roles to the user based on Keycloak claims and configuration
    /// </summary>
    /// <param name="objectSpace">The object space for database operations</param>
    /// <param name="user">The user to assign roles to</param>
    /// <param name="claimsPrincipal">The claims principal containing role information</param>
    protected virtual void AssignUserRoles(IObjectSpace objectSpace, TUser user, ClaimsPrincipal claimsPrincipal)
    {
        // Get or create default role
        var defaultRole = GetOrCreateRole(objectSpace, _options.UserMapping.DefaultRoleName);
        if (defaultRole != null)
        {
            // Use reflection to add role to user's roles collection
            AssignRoleToUser(user, defaultRole);
        }

        // Map additional roles from claims
        foreach (var roleMapping in _options.UserMapping.RoleMappings)
        {
            var keycloakRoleName = roleMapping.Key;
            var xafRoleName = roleMapping.Value;
            
            // Check if user has the Keycloak role (could be in various claim types)
            var hasRole = claimsPrincipal.IsInRole(keycloakRoleName) ||
                         HasClaimValue(claimsPrincipal, "realm_access", keycloakRoleName) ||
                         HasClaimValue(claimsPrincipal, "resource_access", keycloakRoleName);
            
            if (hasRole)
            {
                var role = GetOrCreateRole(objectSpace, xafRoleName);
                if (role != null)
                {
                    AssignRoleToUser(user, role);
                }
            }
        }
    }

    /// <summary>
    /// Assigns a role to a user using reflection
    /// </summary>
    /// <param name="user">The user to assign the role to</param>
    /// <param name="role">The role to assign</param>
    protected virtual void AssignRoleToUser(TUser user, TRole role)
    {
        // Use reflection to access the Roles property on the user
        var userType = user.GetType();
        var rolesProperty = userType.GetProperty("Roles");
        
        if (rolesProperty != null)
        {
            var rolesCollection = rolesProperty.GetValue(user);
            if (rolesCollection != null)
            {
                // Try to add the role using the Add method
                var addMethod = rolesCollection.GetType().GetMethod("Add");
                addMethod?.Invoke(rolesCollection, new object[] { role });
            }
        }
    }

    /// <summary>
    /// Checks if a claims principal has a specific claim value
    /// </summary>
    /// <param name="principal">The claims principal to check</param>
    /// <param name="claimType">The type of claim to look for</param>
    /// <param name="value">The value to search for within the claim</param>
    /// <returns>True if the claim contains the specified value</returns>
    protected virtual bool HasClaimValue(ClaimsPrincipal principal, string claimType, string value)
    {
        var claim = principal.FindFirst(claimType);
        if (claim == null) return false;
        
        // Try to parse as JSON array if it's a complex claim
        try
        {
            if (claim.Value.StartsWith("[") || claim.Value.StartsWith("{"))
            {
                return claim.Value.Contains(value);
            }
        }
        catch
        {
            // Ignore parsing errors
        }
        
        return claim.Value.Contains(value);
    }

    /// <summary>
    /// Gets an existing role or creates a new one if configured to do so
    /// </summary>
    /// <summary>
    /// Gets or creates a role by name
    /// </summary>
    /// <param name="objectSpace">The object space for database operations</param>
    /// <param name="roleName">The name of the role to get or create</param>
    /// <returns>The role object or null if creation failed</returns>
    protected virtual TRole? GetOrCreateRole(IObjectSpace objectSpace, string roleName)
    {
        var role = objectSpace.GetObjects<TRole>().FirstOrDefault(r => 
            GetRoleNameProperty(r)?.Equals(roleName, StringComparison.OrdinalIgnoreCase) == true);
        
        if (role == null && _options.UserMapping.CreateDefaultRoleIfMissing)
        {
            role = objectSpace.CreateObject<TRole>();
            SetRoleNameProperty(role, roleName);
            
            if (role is PermissionPolicyRole policyRole)
            {
                policyRole.IsAdministrative = false;
            }
            
            _logger.LogInformation("Created new role: {RoleName}", roleName);
        }
        
        return role;
    }

    /// <summary>
    /// Finds existing user login info
    /// </summary>
    /// <summary>
    /// Finds a user login info record for the specified provider and key
    /// </summary>
    /// <param name="objectSpace">The object space for database operations</param>
    /// <param name="loginProviderName">The login provider name</param>
    /// <param name="providerUserKey">The provider user key</param>
    /// <returns>The user login info or null if not found</returns>
    protected virtual TUserLoginInfo? FindUserLoginInfo(IObjectSpace objectSpace, string loginProviderName, string providerUserKey)
    {
        return objectSpace.GetObjects<TUserLoginInfo>().FirstOrDefault(userLoginInfo =>
            GetLoginProviderName(userLoginInfo) == loginProviderName &&
            GetProviderUserKey(userLoginInfo) == providerUserKey);
    }

    /// <summary>
    /// Sets a property value on an object if the property exists and is writable
    /// </summary>
    /// <summary>
    /// Sets a property value on an object if the property exists
    /// </summary>
    /// <param name="obj">The object to set the property on</param>
    /// <param name="propertyName">The name of the property</param>
    /// <param name="value">The value to set</param>
    protected virtual void SetPropertyIfExists(object obj, string propertyName, string value)
    {
        if (string.IsNullOrEmpty(value)) return;
        
        try
        {
            var property = obj.GetType().GetProperty(propertyName);
            if (property != null && property.CanWrite && property.PropertyType == typeof(string))
            {
                property.SetValue(obj, value);
                _logger.LogDebug("Set property {PropertyName} = {Value}", propertyName, value);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to set property {PropertyName} on {ObjectType}", propertyName, obj.GetType().Name);
        }
    }

    #region Helper methods for reflection-based property access

    private static string? GetUserNameProperty(TUser user)
    {
        return user.GetType().GetProperty("UserName")?.GetValue(user) as string;
    }

    private static void SetUserNameProperty(TUser user, string userName)
    {
        user.GetType().GetProperty("UserName")?.SetValue(user, userName);
    }

    private static string? GetRoleNameProperty(TRole role)
    {
        return role.GetType().GetProperty("Name")?.GetValue(role) as string;
    }

    private static void SetRoleNameProperty(TRole role, string roleName)
    {
        role.GetType().GetProperty("Name")?.SetValue(role, roleName);
    }

    private static string? GetLoginProviderName(TUserLoginInfo loginInfo)
    {
        return loginInfo.GetType().GetProperty("LoginProviderName")?.GetValue(loginInfo) as string;
    }

    private static string? GetProviderUserKey(TUserLoginInfo loginInfo)
    {
        return loginInfo.GetType().GetProperty("ProviderUserKey")?.GetValue(loginInfo) as string;
    }

    #endregion
}

/// <summary>
/// Helper class for claim type mapping
/// </summary>
internal static class ClaimTypes
{
    public static string GetClaimTypeFromName(string name) => name switch
    {
        "email" => System.Security.Claims.ClaimTypes.Email,
        "given_name" => System.Security.Claims.ClaimTypes.GivenName,
        "family_name" => System.Security.Claims.ClaimTypes.Surname,
        "name" => System.Security.Claims.ClaimTypes.Name,
        _ => name
    };
}