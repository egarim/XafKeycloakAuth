using System.Security.Claims;
using System.Security.Principal;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security;
using DevExpress.Persistent.BaseImpl.EF.PermissionPolicy;
using XafKeycloakAuth.Module.BusinessObjects;

namespace XafKeycloakAuth.Blazor.Server.Services;

/// <summary>
/// Custom authentication provider for Keycloak OpenID Connect integration with XAF Security.
/// This bridges ASP.NET Core authentication with XAF's internal security system.
/// Based on DevExpress documentation: https://docs.devexpress.com/eXpressAppFramework/402197
/// </summary>
public class KeycloakAuthenticationProvider : IAuthenticationProviderV2
{
    private readonly IPrincipalProvider principalProvider;

    public KeycloakAuthenticationProvider(IPrincipalProvider principalProvider)
    {
        this.principalProvider = principalProvider;
    }

    public object Authenticate(IObjectSpace objectSpace)
    {
        if (!CanHandlePrincipal(principalProvider.User))
        {
            return null;
        }

        const bool autoCreateUser = true;

        ClaimsPrincipal claimsPrincipal = (ClaimsPrincipal)principalProvider.User;
        
        // Get user identification claims from Keycloak
        var userIdClaim = claimsPrincipal.FindFirst("sub") ?? 
                         claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier) ?? 
                         throw new InvalidOperationException("Unknown user id - missing 'sub' or NameIdentifier claim");

        var providerUserKey = userIdClaim.Value;
        var loginProviderName = claimsPrincipal.Identity.AuthenticationType;
        
        // Try to get username from preferred_username claim (Keycloak standard) or fall back to Name
        var userName = claimsPrincipal.FindFirst("preferred_username")?.Value ?? 
                      claimsPrincipal.Identity.Name ?? 
                      claimsPrincipal.FindFirst(ClaimTypes.Name)?.Value;

        if (string.IsNullOrEmpty(userName))
        {
            throw new InvalidOperationException("Unable to determine username from Keycloak claims");
        }

        // Look for existing user login info
        var userLoginInfo = FindUserLoginInfo(objectSpace, loginProviderName, providerUserKey);
        if (userLoginInfo != null)
        {
            return userLoginInfo.User;
        }

        // Auto-create user if enabled and not found
        if (autoCreateUser)
        {
            return CreateApplicationUser(objectSpace, claimsPrincipal, userName, loginProviderName, providerUserKey);
        }

        return null;
    }

    private bool CanHandlePrincipal(IPrincipal user)
    {
        return user.Identity.IsAuthenticated &&
               user.Identity.AuthenticationType != SecurityDefaults.Issuer &&
               user.Identity.AuthenticationType != SecurityDefaults.PasswordAuthentication &&
               user.Identity.AuthenticationType != SecurityDefaults.WindowsAuthentication &&
               !(user is WindowsPrincipal) &&
               // Check for Keycloak authentication scheme
               (user.Identity.AuthenticationType == "Keycloak" || 
                user.Identity.AuthenticationType == "OpenIdConnect");
    }

    private object CreateApplicationUser(IObjectSpace objectSpace, ClaimsPrincipal claimsPrincipal, 
        string userName, string loginProviderName, string providerUserKey)
    {
        // Check if user already exists by username
        if (objectSpace.FirstOrDefault<ApplicationUser>(user => user.UserName == userName) != null)
        {
            throw new ArgumentException($"The username ('{userName}') was already registered within the system");
        }

        var user = objectSpace.CreateObject<ApplicationUser>();
        user.UserName = userName;
        
        // Set additional user properties from Keycloak claims
        var emailClaim = claimsPrincipal.FindFirst(ClaimTypes.Email) ?? claimsPrincipal.FindFirst("email");
        // Note: Email property might not be available in this version of PermissionPolicyUser
        // You can add custom properties to ApplicationUser if needed
        
        var givenNameClaim = claimsPrincipal.FindFirst(ClaimTypes.GivenName) ?? claimsPrincipal.FindFirst("given_name");
        var familyNameClaim = claimsPrincipal.FindFirst(ClaimTypes.Surname) ?? claimsPrincipal.FindFirst("family_name");
        var nameClaim = claimsPrincipal.FindFirst("name") ?? claimsPrincipal.FindFirst(ClaimTypes.Name);

        // Try to set first and last name if available and properties exist
        SetPropertyIfExists(user, "FirstName", givenNameClaim?.Value);
        SetPropertyIfExists(user, "LastName", familyNameClaim?.Value);
        SetPropertyIfExists(user, "DisplayName", nameClaim?.Value);
        SetPropertyIfExists(user, "Email", emailClaim?.Value);

        // Generate a random password (required by XAF)
        user.SetPassword(Guid.NewGuid().ToString());
        
        // Assign default role
        var defaultRole = objectSpace.FirstOrDefault<PermissionPolicyRole>(role => role.Name == "Default");
        if (defaultRole != null)
        {
            user.Roles.Add(defaultRole);
        }
        else
        {
            // Create a default role if it doesn't exist
            var newDefaultRole = objectSpace.CreateObject<PermissionPolicyRole>();
            newDefaultRole.Name = "Default";
            newDefaultRole.IsAdministrative = false;
            user.Roles.Add(newDefaultRole);
        }

        // Create user login info for this external authentication
        ((ISecurityUserWithLoginInfo)user).CreateUserLoginInfo(loginProviderName, providerUserKey);
        
        objectSpace.CommitChanges();
        return user;
    }

    private ISecurityUserLoginInfo FindUserLoginInfo(IObjectSpace objectSpace, string loginProviderName, string providerUserKey)
    {
        return objectSpace.FirstOrDefault<ApplicationUserLoginInfo>(userLoginInfo =>
                            userLoginInfo.LoginProviderName == loginProviderName &&
                            userLoginInfo.ProviderUserKey == providerUserKey);
    }

    private void SetPropertyIfExists(object obj, string propertyName, string value)
    {
        if (string.IsNullOrEmpty(value)) return;
        
        var property = obj.GetType().GetProperty(propertyName);
        if (property != null && property.CanWrite && property.PropertyType == typeof(string))
        {
            property.SetValue(obj, value);
        }
    }
}