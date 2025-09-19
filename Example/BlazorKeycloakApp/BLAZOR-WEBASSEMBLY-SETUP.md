# Blazor WebAssembly with Keycloak - Setup Guide

## What's New

I've successfully added a third project to your solution: **BlazorWebAssembly** with Keycloak authentication integration.

## Project Structure

Your solution now contains:
1. **BlazorApi** (REST API) - Runs on https://localhost:7002
2. **BlazorServer** (Server-side Blazor) - Runs on https://localhost:7001  
3. **BlazorWebAssembly** (Client-side Blazor) - Runs on https://localhost:7003

## Key Features of the WebAssembly Project

✅ **Complete Keycloak Integration** - Uses OIDC authentication with public client configuration
✅ **API Test Page** - Same diagnostic tools as BlazorServer (`/api-test` page)
✅ **JWT Token Management** - Automatic token handling with copy-to-clipboard functionality
✅ **Role-based Authorization** - Supports admin/user roles from Keycloak
✅ **CORS Configuration** - API updated to accept requests from WebAssembly app
✅ **Comprehensive Diagnostics** - Full authentication debugging tools

## Quick Setup

### 1. Update Keycloak Configuration

The setup script has been updated to create a **blazor-wasm** client automatically:

```powershell
.\setup-keycloak-complete.ps1
```

**New Keycloak Client Configuration:**
- **Client ID**: `blazor-wasm` 
- **Client Type**: Public (suitable for WebAssembly)
- **PKCE**: Enabled for security
- **Redirect URIs**: Configured for https://localhost:7003
- **Audience Mapper**: Configured for API authentication

### 2. Run All Applications

```powershell
# Terminal 1 - API
cd BlazorApi
dotnet run

# Terminal 2 - Blazor Server  
cd BlazorServer
dotnet run

# Terminal 3 - Blazor WebAssembly (NEW)
cd BlazorWebAssembly
dotnet run
```

### 3. Test Authentication

- **Blazor Server**: https://localhost:7001
- **Blazor WebAssembly**: https://localhost:7003 
- **API Swagger**: https://localhost:7002/swagger

**Test Credentials**: `testuser` / `Test123!`

## Key Differences: Server vs WebAssembly

| Feature | Blazor Server | Blazor WebAssembly |
|---------|---------------|-------------------|
| **Authentication** | Cookie + OpenID Connect | OIDC with public client |
| **Token Storage** | Server-side secure | Browser localStorage |
| **Client Secret** | Required (confidential) | Not needed (public) |
| **Security Model** | Server-side validation | Client-side with JWT |
| **Network** | SignalR connection | Direct HTTP calls |

## WebAssembly-Specific Configuration

### appsettings.json
```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/blazor-app",
    "ClientId": "blazor-wasm",
    "RequireHttpsMetadata": false,
    "ResponseType": "code",
    "Scopes": [ "openid", "profile", "email", "roles" ]
  },
  "ApiSettings": {
    "BaseUrl": "https://localhost:7002"
  }
}
```

**Note**: No `ClientSecret` needed for WebAssembly (public client).

### CORS Configuration Updated

The API now accepts requests from both Blazor applications:

```json
"Cors": {
  "AllowedOrigins": ["https://localhost:7001", "https://localhost:7003"]
}
```

## Troubleshooting

### Common Issues:

1. **"Authentication failed"** 
   - Ensure the `blazor-wasm` client exists in Keycloak
   - Run the updated setup script: `.\setup-keycloak-complete.ps1`

2. **API calls fail with CORS errors**
   - Verify API is running on https://localhost:7002
   - Check CORS configuration includes https://localhost:7003

3. **Token not found errors**
   - WebAssembly uses different token storage than Server
   - Check browser dev tools → Application → Local Storage

### Debugging Tools

Both WebAssembly and Server projects include the same comprehensive API test page at `/api-test`:

- 🔍 **Full Diagnostics** - Complete authentication analysis
- 🎟️ **Token Analysis** - JWT token inspection and validation  
- 🔒 **Endpoint Testing** - Test protected API calls
- ⚙️ **Configuration Check** - Verify all settings
- 📋 **Token Copy** - Copy JWT tokens for Swagger testing

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Blazor Server  │    │ Blazor WebAssembly│    │   Keycloak      │
│  (localhost:7001│ ──▶│  (localhost:7003) │ ──▶│ (localhost:8080)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                        
         └───────────────────────┼────────────────────────
                                 ▼                        
                    ┌─────────────────────────┐            
                    │      Blazor API         │            
                    │   (localhost:7002)      │            
                    │   JWT Bearer Auth       │            
                    └─────────────────────────┘            
```

## Next Steps

1. ✅ **Test Authentication** - Try logging in to both applications
2. ✅ **Test API Integration** - Use the `/api-test` pages  
3. ✅ **Compare Implementations** - See how Server vs WebAssembly handle auth differently
4. ✅ **Copy Tokens** - Use the token copy feature for Swagger testing

The WebAssembly project is now fully integrated and ready to use! 🚀
