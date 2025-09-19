# BlazorKeycloakApp

This repository contains a comprehensive Blazor solution demonstrating authentication with Keycloak, consisting of two applications:
- **BlazorServer**: A Blazor Server application using OpenID Connect authentication
- **BlazorApi**: A Web API using JWT Bearer authentication

## 🚀 Quick Start

### Prerequisites
- .NET 9.0 SDK
- Keycloak server running on http://localhost:8080
- PowerShell (for setup scripts)

### Setup Steps

1. **Start Keycloak** (if not already running)
2. **(Optional) Set environment variables for secure credential management**:
   ```powershell
   $env:KEYCLOAK_ADMIN_PASSWORD = "your-admin-password"  # if different from 'admin'
   ```
3. **Run the automated setup**:
   ```powershell
   .\setup-keycloak-complete.ps1
   ```
3. **⚠️ IMPORTANT: Configure Client Secret**:
   - The setup script will show instructions to get the client secret from Keycloak
   - Open: http://localhost:8080/admin
   - Navigate to: Realms > blazor-app > Clients > blazor-server > Credentials tab
   - Copy the "Client secret" value
   - Update `BlazorServer/appsettings.json`:
   ```json
   {
     "Keycloak": {
       "Authority": "http://localhost:8080/realms/blazor-app",
       "ClientId": "blazor-server",
       "ClientSecret": "YOUR_ACTUAL_CLIENT_SECRET_HERE",
       "RequireHttpsMetadata": false
     }
   }
   ```
4. **Start the applications**:
   ```powershell
   # Terminal 1 - API
   cd BlazorApi
   dotnet run
   
   # Terminal 2 - Blazor Server
   cd BlazorServer
   dotnet run
   ```
5. **Test the application**:
   - Navigate to: https://localhost:7001
   - Login with: `testuser / Test123!`
   - Test API endpoints at: https://localhost:7001/api-test
   - Test with Swagger UI at: https://localhost:7049/swagger

## 🔧 Features & Tools

### 🔍 Comprehensive Diagnostics
The application includes advanced debugging tools accessible at `/api-test`:

- **🔍 Run Full Diagnostics**: Complete authentication analysis
- **🎟️ Analyze Token**: Deep JWT token inspection with audience/issuer validation
- **🔒 Test Protected Endpoint**: Detailed HTTP request/response analysis
- **⚙️ Check Configuration**: Verify all settings
- **📋 Copy Token**: One-click token copying for Swagger testing

### 🔧 Swagger UI with JWT Authentication
Enhanced Swagger UI with JWT Bearer token support:
- **URL**: https://localhost:7002
- **Features**: 
  - JWT Bearer authentication
  - Test all endpoints directly
  - Detailed authentication debugging endpoints
  - Copy tokens directly from Blazor app

### 🛠️ Setup & Management Scripts

| Script | Purpose |
|--------|---------|
| `setup-keycloak-complete.ps1` | **Complete automated setup** - Creates realm, clients, users, roles, and audience mappers |
| `delete-realm.ps1` | **Clean slate** - Safely deletes realm for fresh start |
| `setup-keycloak-complete.ps1 -UpdateOnly` | **Update existing** - Updates client configuration only |

### 🌐 Environment Variables Support

Both scripts support environment variables for secure credential management:

```powershell
# Set environment variables (optional)
$env:KEYCLOAK_URL = "http://localhost:8080"
$env:KEYCLOAK_ADMIN_USER = "admin"
$env:KEYCLOAK_ADMIN_PASSWORD = "your-admin-password"

# Run scripts - they will automatically use environment variables
.\setup-keycloak-complete.ps1
.\delete-realm.ps1
```

**Environment Variables:**
- `KEYCLOAK_URL`: Keycloak server URL (default: http://localhost:8080)
- `KEYCLOAK_ADMIN_USER`: Admin username (default: admin)
- `KEYCLOAK_ADMIN_PASSWORD`: Admin password (default: admin)

**Benefits:**
- ✅ Keep sensitive credentials out of command line history
- ✅ Better security for production environments
- ✅ Easy integration with CI/CD pipelines
- ✅ Backward compatible - parameters still work if environment variables not set

## About Keycloak

Keycloak is an open-source Identity and Access Management solution that provides single sign-on with Identity and Access Management for applications and services. This application uses Keycloak as the central authentication server for both the Blazor Server app and the API.

## 🔐 Authentication Implementation

### BlazorServer Authentication

The Blazor Server application implements OpenID Connect authentication with Cookie authentication for session management:

**Key Features:**
- OpenID Connect with PKCE (Proof Key for Code Exchange) for enhanced security
- Cookie-based session management
- Automatic token storage and refresh
- Role-based authorization with Keycloak realm roles
- Custom error handling and authentication events

**Configuration (`appsettings.json`):**
```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/blazor-app",
    "ClientId": "blazor-server",
    "ClientSecret": "9lUH5Ik00gmPGqM2Ul8144YQ3qmm8mtA",
    "RequireHttpsMetadata": false,
    "ResponseType": "code",
    "SaveTokens": true,
    "GetClaimsFromUserInfoEndpoint": true,
    "Scopes": ["openid", "profile", "email", "roles"]
  },
  "ApiSettings": {
    "BaseUrl": "https://localhost:7002"
  }
}
```

**Authentication Setup:**
- Uses Cookie authentication as the default scheme
- OpenID Connect for challenging unauthenticated users
- Configures callback paths: `/signin-oidc`, `/signout-callback-oidc`, `/signout-oidc`
- Maps Keycloak's `preferred_username` to the Name claim
- Transforms Keycloak realm roles to .NET role claims
- Stores access, refresh, and ID tokens for API calls

**Authorization Policies:**
- `RequireAuthentication`: Requires authenticated user
- `RequireAdmin`: Requires "admin" role
- `RequireUser`: Requires "user" or "admin" role

### BlazorApi Authentication

The API implements JWT Bearer authentication to validate tokens issued by Keycloak:

**Configuration (`appsettings.json`):**
```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/blazor-app",
    "Audience": "blazor-api",
    "RequireHttpsMetadata": false
  },
  "Cors": {
    "AllowedOrigins": ["https://localhost:7001"]
  }
}
```

**Key Features:**
- JWT Bearer token validation
- Keycloak realm role transformation
- CORS configuration for Blazor Server requests
- Token lifetime validation with 5-minute clock skew tolerance
- Custom token validation events for role mapping

**Token Validation:**
- Validates issuer, audience, lifetime, and signing key
- Maps `preferred_username` to Name claim
- Extracts roles from `realm_access.roles` claim
- Supports the same authorization policies as the Blazor Server app

## Keycloak Setup Scripts

### setup-keycloak-complete.ps1 (Recommended)

This comprehensive PowerShell script automates the complete Keycloak configuration:

**Features:**
- **Full Setup**: Creates realm, clients, roles, and test users
- **Update Mode**: Updates existing client configurations
- **Manual Instructions**: Shows step-by-step manual configuration guide
- **Error Handling**: Comprehensive error handling with troubleshooting tips
- **Flexible Parameters**: Customizable URLs, credentials, and client names

**Usage Examples:**
```powershell
# Full automated setup (recommended)
.\setup-keycloak-complete.ps1

# Update existing client configuration only
.\setup-keycloak-complete.ps1 -UpdateOnly

# Show manual configuration instructions
.\setup-keycloak-complete.ps1 -ShowInstructions

# Custom configuration
.\setup-keycloak-complete.ps1 -KeycloakUrl "http://localhost:8080" -AdminUsername "admin" -AdminPassword "admin"
```

**What it does:**
- Creates `blazor-app` realm with proper security settings
- Configures `blazor-server` client (OpenID Connect, confidential)
- Configures `blazor-api` client (JWT Bearer, resource server)
- Sets up comprehensive redirect URIs for all authentication scenarios:
  - `/signin-oidc` - OpenID Connect callback
  - `/signout-callback-oidc` - Logout callback
  - `/authentication/login-callback` - Additional login callback
  - `/authentication/logout-callback` - Additional logout callback
- Creates realm roles: `admin`, `user`, `manager`
- Creates test user: `testuser` / `Test123!`
- Configures PKCE (S256) for enhanced security
- Sets proper token lifespans and session timeouts

### Legacy Scripts (Deprecated)

**setup-keycloak.ps1**: Original setup script - use `setup-keycloak-complete.ps1` instead
**update-keycloak-client.ps1**: Manual instruction guide - integrated into complete script

## Project Structure

### BlazorServer Project
- **Program.cs**: Authentication and authorization configuration
- **Pages/Index.razor**: Protected home page requiring authentication
- **Pages/Welcome.razor**: Public welcome page with login link
- **Services/**: Custom services for authentication and API communication

### BlazorApi Project
- **Program.cs**: JWT authentication and CORS configuration
- **Controllers/**: API endpoints protected with `[Authorize]` attributes

## Setup Instructions

### Prerequisites
- .NET 9 SDK
- PowerShell 7.0+
- Keycloak instance running on `http://localhost:8080`

### Quick Start (Automated Setup)

1. **Start Keycloak** (ensure it's running on localhost:8080)

2. **Run the setup script:**
   ```powershell
   .\setup-keycloak-complete.ps1
   ```
   
   The script will create all necessary configurations but you must manually get the client secret.

3. **⚠️ CRITICAL: Get Client Secret and Update Configuration:**
   
   **Step 3a: Get the Client Secret**
   - Open Keycloak Admin Console: http://localhost:8080/admin
   - Navigate to: Realms > blazor-app > Clients > blazor-server
   - Go to the "Credentials" tab
   - Copy the "Client secret" value
   
   **Step 3b: Update appsettings.json**
   ```json
   // BlazorServer/appsettings.json
   {
     "Keycloak": {
       "Authority": "http://localhost:8080/realms/blazor-app",
       "ClientId": "blazor-server",
       "ClientSecret": "PASTE_YOUR_ACTUAL_CLIENT_SECRET_HERE",
       "RequireHttpsMetadata": false
     }
   }
   ```

4. **Run the applications:**
   ```bash
   # Terminal 1 - API
   cd BlazorApi
   dotnet run
   
   # Terminal 2 - Blazor Server
   cd BlazorServer
   dotnet run
   ```

5. **Test the application:**
   - Navigate to `https://localhost:7001`
   - Click "Login with Keycloak"
   - Use credentials: `testuser` / `Test123!`

### Manual Setup (If Scripts Fail)

If the automated script fails, you can configure Keycloak manually:

```powershell
.\setup-keycloak-complete.ps1 -ShowInstructions
```

This will display detailed step-by-step instructions for manual configuration.

### Troubleshooting

**Common Issues:**

1. **❌ "Unable to obtain configuration" / Authentication Errors**: 
   **MOST COMMON ISSUE** - Missing or incorrect client secret:
   ```powershell
   # Solution: Get the client secret from Keycloak Admin Console
   # 1. Open: http://localhost:8080/admin
   # 2. Go to: Realms > blazor-app > Clients > blazor-server > Credentials
   # 3. Copy the Client secret value
   # 4. Update BlazorServer/appsettings.json with the correct ClientSecret
   ```

2. **Authentication Failed**: Run update script to fix redirect URIs:
   ```powershell
   .\setup-keycloak-complete.ps1 -UpdateOnly
   ```

3. **Token Validation Errors**: Verify API client configuration and realm authority URL

4. **CORS Issues**: Ensure BlazorServer URL is in the API's allowed origins

5. **Logout Redirect Issues**: The complete script configures all necessary logout redirect URIs

## Test Credentials

The application includes test credentials for development:
- **Username**: `testuser`
- **Password**: `Test123!`

## Features

### Core Authentication
- **Secure Authentication**: Full OpenID Connect implementation with Keycloak
- **Role-Based Access Control**: Admin and user roles with different permissions
- **JWT Token Integration**: Seamless token passing between Blazor Server and API
- **Session Management**: Proper login/logout flows with token cleanup
- **API Integration**: Authenticated API calls from Blazor Server to Web API
- **Error Handling**: Comprehensive authentication error handling and logging

### Developer Tools & Diagnostics
- **ApiTest Page**: Comprehensive testing interface with real-time diagnostics
- **Token Analysis**: Detailed JWT token inspection with claims visualization
- **Authentication Diagnostics**: Deep analysis of authentication flow and potential issues
- **Token Copy Functionality**: Easy copying of access tokens for external testing tools
- **API Configuration Validation**: Automated checks for common configuration issues
- **Swagger Integration**: Full JWT authentication support in API documentation

### Testing & Documentation
- **Swagger UI**: Interactive API documentation with JWT Bearer authentication
- **Automated Testing**: Built-in endpoint testing with authentication validation
- **Debugging Tools**: Specialized controllers and services for authentication troubleshooting
- **Comprehensive Logging**: Detailed error reporting and diagnostic information

### Automation & Setup
- **Complete Setup Script**: One-click Keycloak realm and client configuration
- **Audience Mapper Configuration**: Automatic JWT audience claim setup
- **Clean Deletion Script**: Safe realm cleanup for fresh starts
- **Update Scripts**: Easy configuration updates and fixes

## Development Notes

- The application uses HTTPS redirect but allows HTTP for Keycloak in development (`RequireHttpsMetadata: false`)
- PKCE is enabled for enhanced security
- Tokens are automatically stored and managed by the authentication middleware
- Role claims are automatically transformed from Keycloak's realm roles
- CORS is configured to allow requests from the Blazor Server app to the API
- All necessary redirect URIs are pre-configured for seamless authentication flows

## Advanced Tools & Testing

### Swagger UI Integration
The API includes comprehensive Swagger documentation with JWT authentication:

1. **Start the API**: `dotnet run` in the BlazorApi directory
2. **Open Swagger**: Navigate to `https://localhost:7049/swagger`
3. **Authenticate**: Click "Authorize" and enter your JWT token (get it from ApiTest page)
4. **Test Endpoints**: Execute any protected endpoint directly from Swagger

### ApiTest Diagnostic Tools
The enhanced ApiTest page (`/apitest`) provides comprehensive debugging:

- **Real-time Token Analysis**: View JWT claims and validation status
- **Authentication Flow Testing**: Step-by-step verification of auth process
- **API Configuration Checks**: Automatic validation of common setup issues
- **Token Copy Feature**: Easy copying of access tokens for external tools
- **Endpoint Testing**: Direct testing of protected and unprotected endpoints

### Debugging Controllers
The API includes specialized debugging endpoints:

- `/api/authtest/claims` - View current user claims
- `/api/authtest/token-info` - Detailed token analysis
- `/api/authtest/test-auth` - Authentication status verification

### PowerShell Automation Scripts

#### Complete Setup Script
```powershell
# Full automated setup with all features
.\setup-keycloak-complete.ps1

# Update existing configuration only
.\setup-keycloak-complete.ps1 -UpdateOnly

# Show manual setup instructions
.\setup-keycloak-complete.ps1 -ShowInstructions
```

#### Clean Slate Script
```powershell
# Safely delete realm and all associated data
.\delete-realm.ps1

# Confirm deletion (will prompt for confirmation)
.\delete-realm.ps1 -Confirm
```

#### Client Update Script
```powershell
# Update client configuration only
.\update-keycloak-client.ps1
```

### Troubleshooting Tools

#### Authentication Diagnostics Service
The `ApiDiagnosticsService` provides comprehensive analysis:

- Token validation and claims inspection
- API configuration verification
- Authentication flow analysis
- Common issue detection and solutions

#### Common Fixes

1. **Missing Audience Claim**: The setup script now automatically creates audience mappers
2. **CORS Issues**: Pre-configured in both setup script and API startup
3. **Redirect URI Mismatches**: All common URIs are automatically configured
4. **Token Validation Errors**: Enhanced error reporting with specific solutions

### Fresh Start Process

To completely reset and verify everything works:

1. **Delete existing realm**:
   ```powershell
   .\delete-realm.ps1
   ```

2. **Run complete setup**:
   ```powershell
   .\setup-keycloak-complete.ps1
   ```

3. **Test authentication**:
   - Login at `https://localhost:7001`
   - Visit `/apitest` page
   - Run diagnostics
   - Test Swagger UI at `https://localhost:7049/swagger`

## Architecture

### Authentication Flow
1. User initiates login via Blazor Server
2. Redirected to Keycloak for authentication
3. Keycloak returns authorization code
4. Blazor Server exchanges code for tokens
5. Access token used for API calls
6. JWT tokens include proper audience claims for API validation

### Token Management
- Access tokens automatically included in API requests
- Tokens cached and managed by authentication middleware
- Automatic token refresh handled by the framework
- Comprehensive token analysis available via diagnostic tools