# Using Swagger UI for JWT Token Testing

## 🚀 Quick Start Guide

Your API now has enhanced Swagger UI with JWT Bearer authentication support! Here's how to use it:

### 1. Access Swagger UI
- **URL**: https://localhost:7002 
- Swagger UI is now available at the root URL of your API

### 2. Get Your JWT Token
First, get your token from the Blazor app:

1. **Go to your Blazor app**: https://localhost:7001/api-test
2. **Click "Show Current Access Token"** 
3. **Copy the entire token** (it's very long - make sure to get all of it)

### 3. Authenticate in Swagger
1. **Click the "Authorize" button** 🔒 (top-right in Swagger UI)
2. **Enter your token**: `Bearer YOUR_JWT_TOKEN_HERE`
   - **Format**: `Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6...` 
   - **Important**: Include the word "Bearer" followed by a space, then your token
3. **Click "Authorize"**
4. **Click "Close"**

### 4. Test API Endpoints

## 📋 Available Test Endpoints

### **Public Endpoints (No Authentication)**
- **GET** `/api/values` - Basic values (test API connectivity)
- **GET** `/api/authtest/ping` - API health check

### **Authentication Required**
- **GET** `/api/authtest/auth-required` - Basic auth test
- **GET** `/api/authtest/analyze-token` - **⭐ BEST FOR DEBUGGING** - Shows detailed token analysis
- **GET** `/api/values/protected` - Protected values
- **GET** `/api/user/profile` - User profile with all claims

### **Admin Role Required**
- **GET** `/api/authtest/admin-required` - Admin auth test
- **GET** `/api/values/admin-only` - Admin-only values  
- **GET** `/api/user/admin-only` - Admin-only user data

### **User Role Required**
- **GET** `/api/authtest/user-required` - User auth test
- **GET** `/api/user/user-data` - User or admin data

## 🔍 Debugging Steps

### Step 1: Test Basic Connectivity
1. Try **GET** `/api/authtest/ping` (no auth required)
2. Should return `200 OK` with API info

### Step 2: Test Authentication
1. **Authorize in Swagger** with your JWT token
2. Try **GET** `/api/authtest/auth-required`
3. **Expected**: `200 OK` with success message
4. **If 401**: Your token is invalid, expired, or not properly formatted

### Step 3: Analyze Your Token
1. Try **GET** `/api/authtest/analyze-token`
2. **This endpoint shows detailed token information**:
   - Token validity and expiration
   - Audience and issuer
   - All claims and roles
   - Policy validation results

### Step 4: Test Role-Based Access
1. Try **GET** `/api/authtest/user-required` (needs user or admin role)
2. Try **GET** `/api/authtest/admin-required` (needs admin role)
3. Check responses for role validation results

## 🛠️ Common Issues & Solutions

### Issue: "401 Unauthorized"
**Causes**:
- Token expired (check `/api/authtest/analyze-token` response)
- Token not properly formatted in Authorization header
- Audience mismatch between token and API

**Solutions**:
1. Get a fresh token from Blazor app
2. Ensure format is: `Bearer eyJhbGciOiJSUzI1NiIs...`
3. Check token analysis for audience/issuer issues

### Issue: "403 Forbidden" 
**Causes**:
- Token is valid but user lacks required role
- Role claims not properly mapped

**Solutions**:
1. Check `/api/authtest/analyze-token` for role information
2. Verify user has correct roles in Keycloak
3. Check role mapping configuration

### Issue: CORS Errors
**Causes**:
- Browser blocking cross-origin requests from Swagger UI

**Solutions**:
- Use the Swagger UI directly (not embedded in another page)
- Check browser console for specific CORS errors

## 📊 Expected Token Analysis Output

When you call `/api/authtest/analyze-token`, you should see:

```json
{
  "authenticationStatus": {
    "isAuthenticated": true,
    "authenticationType": "Bearer",
    "name": "testuser"
  },
  "tokenInfo": {
    "payload": {
      "issuer": "http://localhost:8080/realms/blazor-app",
      "audiences": ["blazor-api"],
      "isExpired": false
    }
  },
  "roles": {
    "realmRoles": ["user", "admin"],
    "hasAdminRole": true,
    "hasUserRole": true
  },
  "policies": {
    "requireAdmin": true,
    "requireUser": true
  }
}
```

## 🎯 Key Points for Debugging

1. **Audience**: Should be `["blazor-api"]`
2. **Issuer**: Should be `http://localhost:8080/realms/blazor-app`
3. **Expired**: Should be `false`
4. **Roles**: Should include your assigned roles (user/admin)

If any of these are wrong, that's likely your authentication issue!

## 🔧 Next Steps

1. **Test public endpoints first** to verify API is working
2. **Use the analyze-token endpoint** to debug authentication issues
3. **Check browser console** for any JavaScript errors
4. **Compare token analysis** with expected values above

The Swagger UI provides a much easier way to test and debug your JWT authentication compared to the Blazor app!
