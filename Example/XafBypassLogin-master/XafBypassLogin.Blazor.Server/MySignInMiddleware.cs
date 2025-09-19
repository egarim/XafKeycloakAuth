using DevExpress.ExpressApp.Blazor.Services;
using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using XafBypassLogin.Module.BusinessObjects;
using DevExpress.ExpressApp.Core;
using DevExpress.Data.Filtering;

namespace XafBypassLogin.Blazor.Server
{
    public class MySignInMiddleware
    {
        private readonly RequestDelegate next;
        public MySignInMiddleware(RequestDelegate next)
        {
            this.next = next;
        }
        public async Task Invoke(HttpContext context)
        {
            string userName = context.Request.Query["User"];
            
            if (!(context.User?.Identity?.IsAuthenticated ?? false) && !string.IsNullOrEmpty(userName))
            {
                try
                {
                    // Get the SignInManager service
                    var signInManager = context.RequestServices.GetRequiredService<SignInManager>();

                    // Try to sign in with empty password first (default for Admin user)
                    var authResult = signInManager.SignInByPassword(userName, "");
                    
                    if (authResult.Succeeded)
                    {
                        // Establish persistent authentication cookie
                        await context.SignInAsync(authResult.Principal);
                        context.Response.Redirect("/");
                        return;
                    }
                }
                catch (Exception)
                {
                    // Authentication failed, continue to normal login flow
                }
            }

            await next(context);
        }
    }
    public class XAFApplicationInitializer
    {
        bool isInitialized = false;
        readonly object lockObj = new object();

        public void EnsureInit(IXafApplicationProvider xafApplicationProvider)
        {
            if (!isInitialized)
            {
                lock (lockObj)
                {
                    if (!isInitialized)
                    {
                        xafApplicationProvider.GetApplication();
                        isInitialized = true;
                    }
                }
            }
        }
    }
}
