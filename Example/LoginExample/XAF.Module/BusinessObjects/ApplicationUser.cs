using System.ComponentModel;
using System.Text;
using DevExpress.ExpressApp;
using DevExpress.ExpressApp.Security;
using DevExpress.Persistent.BaseImpl.PermissionPolicy;
using DevExpress.Xpo;

namespace XAF.Module.BusinessObjects;

[MapInheritance(MapInheritanceType.ParentTable)]
[DefaultProperty(nameof(UserName))]
public class ApplicationUser : PermissionPolicyUser, IObjectSpaceLink, ISecurityUserWithLoginInfo
{
    public ApplicationUser(Session session) : base(session) { }


    bool autoLoginByURL = false;

    public bool AutoLoginByURL
    {
        get => autoLoginByURL;
        set => SetPropertyValue(nameof(AutoLoginByURL), ref autoLoginByURL, value);
    }
    [Browsable(false)]
    [Aggregated, Association("User-LoginInfo")]
    public XPCollection<ApplicationUserLoginInfo> LoginInfo
    {
        get { return GetCollection<ApplicationUserLoginInfo>(nameof(LoginInfo)); }
    }

    IEnumerable<ISecurityUserLoginInfo> IOAuthSecurityUser.UserLogins => LoginInfo.OfType<ISecurityUserLoginInfo>();

    IObjectSpace IObjectSpaceLink.ObjectSpace { get; set; }

    ISecurityUserLoginInfo ISecurityUserWithLoginInfo.CreateUserLoginInfo(string loginProviderName, string providerUserKey)
    {
        ApplicationUserLoginInfo result = ((IObjectSpaceLink)this).ObjectSpace.CreateObject<ApplicationUserLoginInfo>();
        result.LoginProviderName = loginProviderName;
        result.ProviderUserKey = providerUserKey;
        result.User = this;
        return result;
    }
}
