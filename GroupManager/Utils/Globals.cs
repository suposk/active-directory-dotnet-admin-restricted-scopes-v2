﻿using System.Configuration;

namespace GroupManager.Utils
{
    public static class Globals
    {
        public const string ConsumerTenantId = "1ff35017-cbf2-4700-9930-3210afb6182b";
        public const string IssuerClaim = "iss";
        //public const string Authority = "https://login.microsoftonline.com/common/v2.0/"; 
        //https://login.microsoftonline.com/{tenant-id}/v2.0
        public static string Authority = $"https://login.microsoftonline.com/{ConsumerTenantId}/v2.0/"; 
        public const string RedirectUri = "https://localhost:44321/";
        public const string TenantIdClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";
        public const string MicrosoftGraphGroupsApi = "https://graph.microsoft.com/v1.0/groups";
        public const string MicrosoftGraphUsersApi = "https://graph.microsoft.com/v1.0/users";
        public const string AdminConsentFormat = "https://login.microsoftonline.com/{0}/adminconsent?client_id={1}&state={2}&redirect_uri={3}";
        //public const string BasicSignInScopes = "openid profile email offline_access user.readbasic.all";
        public const string BasicSignInScopes = "openid profile offline_access user.read";        //works
        //public const string BasicSignInScopes = "openid profile offline_access user.read https://management.azure.com/";        //no
                public const string NameClaimType = "name";

        /// <summary>
        /// The Client ID is used by the application to uniquely identify itself to Azure AD.
        /// </summary>
        public static string ClientId { get; } = ConfigurationManager.AppSettings["ida:ClientId"];

        /// <summary>
        /// The ClientSecret is a credential used to authenticate the application to Azure AD.  Azure AD supports password and certificate credentials.
        /// </summary>
        public static string ClientSecret { get; } = ConfigurationManager.AppSettings["ida:ClientSecret"];

        /// <summary>
        /// The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        /// </summary>
        public static string PostLogoutRedirectUri { get; } = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        /// <summary>
        /// The TenantId is the DirectoryId of the Azure AD tenant being used in the sample
        /// </summary>
        public static string TenantId { get; } = ConfigurationManager.AppSettings["ida:TenantId"];
    }
}