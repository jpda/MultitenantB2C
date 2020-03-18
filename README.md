# ♫ any app, any id, with azure ad and b2c ♫

This is an opinionated repository intended to address scenarios of authenticating users from anywhere, leveraging available tools across audiences. This is a common scenario in SaaS apps, especially when delegating administration to customers. Typically SaaS providers host and manage data _for their customers_; this is a critical distinction - as a SaaS provider, we want to reduce or eliminate any friction to using or onboarding customers, offering mechanisms to control & manage access according to their policies, especially corporate/enterprise customers who already have investments in tools & processes.

Depending on your user mix, existing systems and requirements, you may elect to use some or all of these policies, but they are intended as a starting point, an extended sample of what's possible rather than a turn-key solution.

For this scenario, we have four major sources of users:

- **[Azure AD]** Azure AD customers (Office 365, Azure, Dynamics), allowing _customer_ administrators to control policies such as user role assignment and [conditional access](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview){:target="_blank"};
- **[External federation]** Customers who want to directly federate (e.g., a point-to-point federation with ADFS or PingFederate),
- **[Social]** Customers who want to use social accounts (e.g., Facebook, Google, Microsoft consumer, etc), and
- **[Local]** Customers who want to create a new username & password

We address each of these audiences using a combination of available tools:

- Azure AD customers via Azure AD multitenancy
- B2C for social, local & external federation services
- REST services for enriching user data throughout the authentication pipeline

Using B2C as the orchestrator, we centralize and abstract tasks like home realm discovery and authorization metadata, simplifying applications that rely on B2C for identity.

//todo: diagram

## Tenancy

When building multitenant apps, we typically have some construct within our apps of a 'tenant' or 'organization.' That construct is foundational in Azure AD (by design), but more fluid when dealing with social & local accounts. Because of this, the 'tenant' construct will still be prevalent throughout your multitenant application - while AAD and external fed users will have more metadata available to know or infer tenancy (by virtue of the identity provider authenticating them), social and local accounts will need to be assigned a tenancy within your apps/data.

## Authorization metadata

In Azure AD (not B2C), we're able to expose [appRoles](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps){:target="_blank"} via the AAD manifest for a specific app. These roles are managed & assigned within the AAD administrative portal, giving admins a way to assign users/groups to roles which would then flow through to the app during signin. B2C doesn't have this concept, instead relying on custom attributes for authorization. For our scenario, we don't want to lose the rich control Azure AD administrators are granted, instead we passthrough appRoles from Azure AD customers. For externally federated accounts, we can rely on the federation partner to provide role claims (e.g., as part of an onboarding or configuration doc), or keep a local database. Similarly, for social and local accounts, as those accounts have no external administrative 'organization,' we're required to own this experience in total.

In the Azure AD & appRole experience, we get these things for 'free' in that we don't need to build them:

- Implicit tenancy
- Interface for administrators
- Groups
- Assignment of users/groups to roles

As we have users from beyond Azure AD, we'll need to implement these things on our own, either within our app or through some other kind of interface.

| Azure AD | External fed | Social | Local |
|----------|--------------|--------|-------|
| AAD app roles | externally managed, or local store | local store | local store |

### Authorization metadata stores for local & social users

For a local store, we should expose this via REST API to allow B2C to retrieve role data for a user during sign-in, or potentially store role data on the user's object directly. Storing on the object directly offers some benefits, e.g., no REST dependency during sign-in, only during assignment. You may also have an existing authorization system which can be queried by B2C, either at runtime or written to the user object.

| Type | Storage | Interaction | Responsible party |
|------|---------|-------------|-------------------|
| AAD  | AAD | AAD portal | customer admin |
| External fed | External system | External system | customer admin |
| Local/social | database or user object | your portal | SaaS provider |

## Apps

There are two primary mechanisms for using B2C with multi-tenant AAD apps. One is to launder everything through B2C, so your app is effectively 'single-tenant' in that it trusts only a single tenant (B2C).
This has some cost and migration implications, however, so an alternative is to dual-home your app, using both AAD and B2C. AAD users from any Azure AD tenant can login via the multi-tenant path, while B2C users login through a B2C path.
Beyond just commercial/global Azure AD, you may also want to sign users in from Azure China, Azure Government and Azure Germany (for now, Azure DE is on it's way out).

Two examples of integrating an app with multitenant AAD and B2C.

- [Dual-homed app](MultitenantB2C.OpenId/)
- [Multitenancy via B2C](MultitenantB2C.SingleHomed/) with custom policy

## Policies

The included policies include four primary concepts:

- Social and local account support (GitHub & Facebook configured)
- Adding a 'bridge' to the Azure AD ecosystem via Azure AD multitenancy (e.g., the 'common' endpoint)
- Basics of authorization metadata: App Role passthrough from Azure AD, REST services for everyone else

The included policies include different mechanisms for home realm discovery (HRD). HRD is important, especially if your scenario requires many distinct identity providers. Consider a scenario where you may use Azure AD multitenancy for Azure AD users, social or local for other users, but also have customers who are not Azure AD customers who want to federate directly with something like ADFS. Rather than presenting a list of all identity providers (which could be prohibitively long), we can use HRD to determine which IdP to send a user to based on criteria. This could be email address, email suffix, etc. 