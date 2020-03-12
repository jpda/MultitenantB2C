using System.Linq;
using System.Security.Claims;
using Microsoft.Identity.Client;

namespace MultitenantB2C.SingleHomed
{
    public class AzureAdB2COptions
    {
        public const string PolicyAuthenticationProperty = "Policy";

        public AzureAdB2COptions()
        {
        }

        public string ClientId { get; set; }
        public string Tenant { get; set; }
        public string SignUpSignInPolicyId { get; set; }
        public string SignInPolicyId { get; set; }
        public string SignUpPolicyId { get; set; }
        public string ResetPasswordPolicyId { get; set; }
        public string EditProfilePolicyId { get; set; }
        public string RedirectUri { get; set; }

        public string DefaultPolicy => SignUpSignInPolicyId;
        public string Authority => $"https://{Tenant}.b2clogin.com/tfp/{Tenant}.onmicrosoft.com/{DefaultPolicy}/v2.0";

        public string ClientSecret { get; set; }
        public string ApiUrl { get; set; }
        public string ApiScopes { get; set; }
    }
}
