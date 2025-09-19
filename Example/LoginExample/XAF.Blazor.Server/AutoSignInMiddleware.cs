using DevExpress.Data.Filtering;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp.Xpo;
using DevExpress.Persistent.BaseImpl.PermissionPolicy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using XAF.Module.BusinessObjects;

namespace XAF.Blazor.Server
{
    public class AutoSignInMiddleware
    {
        private readonly RequestDelegate next;
        private IConfiguration configuration;
        public AutoSignInMiddleware(IConfiguration config, RequestDelegate next)
        {
            configuration = config;
            this.next = next;
        }
        private static async Task SignIn(HttpContext context, PermissionPolicyUser user, string userName)
        {
            ClaimsIdentity id = new ClaimsIdentity(SecurityDefaults.Issuer);
            Claim claim = new Claim(ClaimTypes.NameIdentifier, user.Oid.ToString(), ClaimValueTypes.String, SecurityDefaults.Issuer);
            id.AddClaim(claim);
            await context.SignInAsync(new ClaimsPrincipal(id));
            context.Response.Redirect("/");
        }
        public async Task Invoke(HttpContext context)
        {
            string userId = context.Request.Query["UserID"];
            Guid userOid = Guid.Empty;
            if (Guid.TryParse(userId, out userOid))
            {
                if (!(context.User?.Identity.IsAuthenticated ?? false) && !string.IsNullOrEmpty(userId))
                {
                    bool autoLoginOK = false;
                    if (configuration.GetConnectionString("ConnectionString") != null)
                    {
                        using (XPObjectSpaceProvider directProvider = new XPObjectSpaceProvider(configuration.GetConnectionString("ConnectionString")))
                        using (IObjectSpace directObjectSpace = directProvider.CreateObjectSpace())
                        {
                            ApplicationUser myUser = directObjectSpace.FindObject<ApplicationUser>(CriteriaOperator.Parse("Oid=?", userOid));
                            if (myUser != null)
                                if (myUser.AutoLoginByURL) 
                                {
                                    autoLoginOK = true;
                                }
                        }
                    }

                    if (autoLoginOK)
                    {
                        ClaimsIdentity id = new ClaimsIdentity(SecurityDefaults.DefaultClaimsIssuer);
                        Claim claim = new Claim(ClaimTypes.NameIdentifier, userId, ClaimValueTypes.String, SecurityDefaults.Issuer);
                        id.AddClaim(claim);
                        await context.SignInAsync(new ClaimsPrincipal(id));
                        context.Response.Redirect("/");
                    }
                    else
                        await next(context);
                }
                else
                    await next(context);
            }
            else
            {
                await next(context);
            }
        }
    }
}
