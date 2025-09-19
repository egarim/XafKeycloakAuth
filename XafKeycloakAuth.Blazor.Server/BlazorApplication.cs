using DevExpress.ExpressApp;
using DevExpress.ExpressApp.ApplicationBuilder;
using DevExpress.ExpressApp.Blazor;
using DevExpress.ExpressApp.Updating;
using DevExpress.ExpressApp.Security;
using DevExpress.ExpressApp.Security.ClientServer;
using DevExpress.ExpressApp.SystemModule;
using XafKeycloakAuth.Module.BusinessObjects;
using Microsoft.EntityFrameworkCore;
using DevExpress.ExpressApp.EFCore;
using DevExpress.EntityFrameworkCore.Security;

namespace XafKeycloakAuth.Blazor.Server;

public class XafKeycloakAuthBlazorApplication : BlazorApplication {
    public XafKeycloakAuthBlazorApplication() {
        ApplicationName = "XafKeycloakAuth";
        CheckCompatibilityType = DevExpress.ExpressApp.CheckCompatibilityType.DatabaseSchema;
        DatabaseVersionMismatch += XafKeycloakAuthBlazorApplication_DatabaseVersionMismatch;
    }
    protected override void OnSetupStarted() {
        base.OnSetupStarted();

#if DEBUG
        if(System.Diagnostics.Debugger.IsAttached && CheckCompatibilityType == CheckCompatibilityType.DatabaseSchema) {
            DatabaseUpdateMode = DatabaseUpdateMode.UpdateDatabaseAlways;
        }
#endif
    }
    void XafKeycloakAuthBlazorApplication_DatabaseVersionMismatch(object sender, DatabaseVersionMismatchEventArgs e) {
        // Always update the database for development purposes
        e.Updater.Update();
        e.Handled = true;
    }
}
