# Authentication Troubleshooting Guide

## Summary of Enhanced Diagnostics

I've added comprehensive diagnostics to your application to help identify why authenticated API calls are failing. Here's what was added:

### 1. Enhanced ApiTest.razor Page
- **🔍 Run Full Diagnostics**: Comprehensive authentication analysis
- **🎟️ Analyze Token**: Deep JWT token inspection with audience/issuer validation
- **🔒 Test Protected Endpoint**: Detailed HTTP request/response analysis
- **⚙️ Check Configuration**: Verify all configuration settings

### 2. New ApiDiagnosticsService
- Token validation and parsing
- HTTP request/response detailed logging
- Configuration verification
- Audience and issuer checking

### 3. Enhanced ApiService
- Better error reporting with specific authentication guidance
- Token expiration checking
- Detailed request/response logging

## How to Use the New Diagnostics

1. **Navigate to /api-test** in your running Blazor app
2. **Click "🔍 Run Full Diagnostics"** to get a complete overview
3. **Click "🎟️ Analyze Token"** to inspect your JWT token details
4. **Click "🔒 Test Protected Endpoint"** for detailed HTTP analysis

## Most Likely Issues & Solutions

### Issue 1: Audience Mismatch (Most Common)

**Problem**: Your JWT token doesn't include the expected audience that the API is looking for.

**How to Check**:
1. Run "🎟️ Analyze Token" and look for "AUDIENCE CHECK"
2. Compare "Expected" vs "Token Audiences"

**Solution**: 
Update your Keycloak client configuration to include the correct audience:

```powershell
# Run this to update your Keycloak client
.\setup-keycloak-complete.ps1 -UpdateOnly
```

Or manually in Keycloak Admin Console:
1. Go to Clients > blazor-server > Client scopes
2. Add "audience" mapper with value "blazor-api"

### Issue 2: Role Claims Not Mapped

**Problem**: Roles aren't being properly extracted from the Keycloak token.

**How to Check**:
1. Run "🔍 Run Full Diagnostics" and check section "3. USER ROLES AND CLAIMS"
2. Look for "Role Claims Count: 0" or missing admin/user roles

**Solution**: Ensure role mapping is working:
- Check that your user has the correct roles assigned in Keycloak
- Verify the API's role transformation logic in `Program.cs`

### Issue 3: Token Expiration

**Problem**: Your access token has expired (default is 5 minutes in your setup).

**How to Check**:
1. Run "🎟️ Analyze Token" and look for "Is Expired: ❌ YES"

**Solution**: 
- Refresh your browser page to get a new token
- Or extend token lifetime in Keycloak (Realm Settings > Tokens)

### Issue 4: API Configuration

**Problem**: The API isn't configured correctly to validate tokens.

**How to Check**:
1. Run "⚙️ Check Configuration"
2. Compare Blazor Server config with expected API config

**Verify API appsettings.json**:
```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/blazor-app",
    "Audience": "blazor-api",
    "RequireHttpsMetadata": false
  }
}
```

### Issue 5: CORS Problems

**Problem**: Cross-origin requests being blocked.

**How to Check**:
1. Open browser Developer Tools (F12)
2. Look for CORS errors in the Console tab
3. Check Network tab for failed OPTIONS requests

**Solution**:
Ensure API's `appsettings.json` has:
```json
{
  "Cors": {
    "AllowedOrigins": ["https://localhost:7001"]
  }
}
```

## Step-by-Step Debugging Process

1. **Start with Full Diagnostics**:
   - Click "🔍 Run Full Diagnostics"
   - Look for any obvious issues in sections 1-4

2. **Check Token Details**:
   - Click "🎟️ Analyze Token"
   - Verify audience matches "blazor-api"
   - Verify issuer matches your Authority URL
   - Check that token is not expired

3. **Test Specific Endpoint**:
   - Click "🔒 Test Protected Endpoint"
   - Check HTTP status code (401 = unauthorized, 403 = forbidden)
   - Review request/response headers

4. **Verify Configuration**:
   - Click "⚙️ Check Configuration"
   - Ensure all URLs and settings match between Blazor Server and API

## Common Error Messages and Solutions

### "Error 401: Unauthorized"
- **Cause**: Token missing, invalid, or expired
- **Fix**: Check token analysis for expiration or format issues

### "Error 403: Forbidden" 
- **Cause**: User lacks required role/permission
- **Fix**: Check role claims in diagnostics, verify user has correct roles in Keycloak

### "No access token available"
- **Cause**: Token not being saved or retrieved properly
- **Fix**: Verify `SaveTokens: true` in appsettings.json

### CORS errors in browser console
- **Cause**: API CORS configuration
- **Fix**: Update API CORS settings to allow Blazor Server origin

## Next Steps

1. **Run the diagnostics** and share the results if issues persist
2. **Check browser console** for any JavaScript errors
3. **Review API logs** for authentication failures
4. **Verify Keycloak client configuration** matches the setup script output

The enhanced diagnostics should give you detailed information about exactly where the authentication is failing. Focus on the audience and role mapping issues first, as these are the most common problems.
