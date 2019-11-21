# MultitenantB2C.OpenId

There are two primary mechanisms for using B2C with multi-tenant AAD apps. One is to launder everything through B2C, so your app is effectively 'single-tenant' in that it trusts only a single tenant (B2C).
This has some cost and migration implications, however, so an alternative is to dual-home your app, using both AAD and B2C. AAD users from any Azure AD tenant can login via the multi-tenant path, while B2C users login through a B2C path. 
Beyond just commercial/global Azure AD, you may also want to sign users in from Azure China, Azure Government and Azure Germany (for now, Azure DE is on it's way out).

This first sample illustrates multi-homed, although an example with B2C custom policy is forthcoming. 

## OpenIdConnect
This uses the generic OpenIdConnect providers since the AzureAD.UI and AzureADB2C.UI extensions [have a bug when using both](https://github.com/aspnet/AspNetCore/issues/11972).

## valid issuers
Since we're using multitenancy in AAD, we have a potentially enormous valid issuer list. Instead of having a static list, this uses the metadata endpoints to pull down the openid metadata for the different authorities (meta-metadata?) and use the issuer templates within to determine if there is a match.
See [here](https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/blob/master/Microsoft.Identity.Web/Resource/AadIssuerValidator.cs) for a potentially more robust issuer validator. 
B2C will be a single valid issuer, so no need to jump through validation hoops for B2C. Each cloud (Commercial/global AAD, China, Gov) will have their own endpoints and issuer values, so at runtime this is driven by the authority (e.g., login.microsoftonline.com, login.partner.microsoftonline.cn, login.microsoftonline.us/de).

## choosing an authentication path
There is an AuthController with buttons to login for each provider. Each button goes to a specific controller action that enforces a specific policy attribute (e.g., `/auth/azuread` uses `Authorize(AuthenticationPolicies = 'AzureAd')`) that pushes a user down a specific authentication path.
This uses a basic `RequireAuthenticatedUser` authorization policy, so any authenticated user can see protected pages. 

## todo
- add similar options for validating api bearer tokens
- add role data to users during sign-in for more authz
- get some data from graph
- clean up and move issuer validator to it's own class
- tbd