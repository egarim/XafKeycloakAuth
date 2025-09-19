# Keycloak Configuration for Blazor WebAssembly

## Important: Keycloak Client Configuration

Make sure your Keycloak client `blazor-wasm` is configured with the following settings:

### 1. Client Settings:
- **Client Type**: `OpenID Connect`
- **Client authentication**: `Off` (Public client)
- **Authorization**: `Off`
- **Standard flow**: `Enabled`
- **Direct access grants**: `Enabled` (optional)
- **Service accounts roles**: `Off`

### 2. Valid Redirect URIs:
```
https://localhost:7003/authentication/login-callback
```

### 3. Valid Post Logout Redirect URIs:
```
https://localhost:7003/authentication/logout-callback
https://localhost:7003/
```

### 4. Web Origins:
```
https://localhost:7003
```

### 5. Client Scopes:
Make sure the following scopes are assigned:
- `openid` (default)
- `profile` (default)
- `email` (default)
- `roles` (optional)

### 6. Advanced Settings:
- **PKCE Code Challenge Method**: `S256`
- **Access Token Lifespan**: `15 minutes` (or as needed)

## Troubleshooting Steps:

1. **Check Keycloak Logs**: Look for authentication errors in Keycloak admin console
2. **Verify Client Configuration**: Ensure all redirect URIs match exactly
3. **Check Browser Network Tab**: Look for failed requests during authentication
4. **Clear Browser Cache**: Clear all cookies and local storage for localhost:5001

## Testing the Fix:

1. Run the Blazor WebAssembly app: `dotnet run --launch-profile https`
2. Navigate to `https://localhost:7003`
3. Click "Log in" link
4. Should redirect to Keycloak login page
5. After successful login, should redirect back to the app
6. Visit `/authtest` page to see authentication details

## Common Issues:

1. **Invalid action ''**: Fixed by creating proper Authentication.razor page
2. **RemoteAuthenticatorView errors**: Fixed by using correct child content templates
3. **404 on AuthenticationService.js**: Fixed by adding the script reference
4. **Authorization failed**: Should be resolved with proper authentication flow
