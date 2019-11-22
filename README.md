# MultitenantB2C

There are two primary mechanisms for using B2C with multi-tenant AAD apps. One is to launder everything through B2C, so your app is effectively 'single-tenant' in that it trusts only a single tenant (B2C).
This has some cost and migration implications, however, so an alternative is to dual-home your app, using both AAD and B2C. AAD users from any Azure AD tenant can login via the multi-tenant path, while B2C users login through a B2C path. 
Beyond just commercial/global Azure AD, you may also want to sign users in from Azure China, Azure Government and Azure Germany (for now, Azure DE is on it's way out).

Two examples of integrating an app with multitenant AAD and B2C.

- [Dual-homed app](MultitenantB2C.OpenId/)
- [Multitenancy via B2C](MultitenantB2C.SingleHomed/) with custom policy
