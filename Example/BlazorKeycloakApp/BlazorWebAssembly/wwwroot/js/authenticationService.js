// Custom AuthenticationService for Keycloak OIDC in Blazor WebAssembly
window.AuthenticationService = {
    init: function (settings) {
        console.log('AuthenticationService initialized with settings:', settings);
        
        // Store settings for use in other methods
        this.settings = settings;
        
        // Return a resolved promise to indicate successful initialization
        return Promise.resolve();
    },
    
    signIn: function (state) {
        console.log('AuthenticationService.signIn called with state:', state);
        // This will be handled by the OIDC provider configuration
        return Promise.resolve();
    },
    
    completeSignIn: function (url) {
        console.log('AuthenticationService.completeSignIn called with URL:', url);
        // This will be handled by the OIDC provider configuration
        return Promise.resolve();
    },
    
    signOut: function (state) {
        console.log('AuthenticationService.signOut called with state:', state);
        // This will be handled by the OIDC provider configuration
        return Promise.resolve();
    },
    
    completeSignOut: function (url) {
        console.log('AuthenticationService.completeSignOut called with URL:', url);
        // This will be handled by the OIDC provider configuration
        return Promise.resolve();
    },
    
    getUser: function () {
        console.log('AuthenticationService.getUser called');
        // This will be handled by the OIDC provider configuration
        return Promise.resolve(null);
    }
};

console.log('AuthenticationService object created and attached to window');
