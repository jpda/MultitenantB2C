# AAD Multitenancy laundered via B2C

This sample uses B2C custom policies for AAD multitenancy. In this example, the application is simplified because it only relies on a single identity provider, B2C, while B2C's configuration becomes more complex to support an additional identity provider.

There are advantages to this approach, especially for keeping application code simple or for processing identities at the identity provider rather than doing it yourself within application code. 

## using this sample
The application code for this sample doesn't deviate much from the out-of-the-box B2C samples. Using the `Microsoft.AspNetCore.Authentication.AzureADB2C.UI` package, we get some AuthenticationBuilder extensions that, provided the configuration exists, is straightforward to add:

```csharp
services.AddAzureADB2C(options => Configuration.Bind(options, "AzureADB2C"));
```

Your configuration object should look like this, replacing with values for your tenant.

```json
 "AzureAdB2C": {
    "Instance": "https://B2C_NAME.b2clogin.com/tfp/",
    "ClientId": "CLIENT_ID",
    "ClientSecret": "CLIENT_SECRET",
    "RedirectUriRoot": "https://localhost:5001",
    "CallbackPath": "/signin-b2c",
    "Domain": "B2C_DOMAIN.onmicrosoft.com",
    "SignUpSignInPolicyId": "B2C_POLICY_ID",
    "ResetPasswordPolicyId": "B2C_POLICY_ID",
    "EditProfilePolicyId": ""
  }
 ```

## B2C configuration
You'll find the appropriate custom policy files in the [B2CPolicies](https://github.com/jpda/MultitenantB2C/tree/master/MultitenantB2C.SingleHomed/B2CPolicies) folder. These policies need to be uploaded in order (e.g., 00-, 01-, etc). You can download fresh base policies from [here](https://github.com/Azure-Samples/active-directory-b2c-custom-policy-starterpack/){:target=_blank}.
Most of the policy files will only need minor changes for your environment - e.g., the name of your B2C tenant (`YOUR_TENANT_HERE` in the included policy files). You'll also need to make sure your B2C tenant is setup to work with IEF, including additional app registrations for Azure AD, which you can find [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-get-started-custom?tabs=applications).

## todo
- add authz sample/code redemption
- issuer validation via REST
- tbd