using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace MultitenantB2C.OpenId
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddOpenIdConnect(AzureAdOptions.AuthenticationScheme, o =>
                {
                    var prefixValidator = new AzureAdTenantIssuerPrefixValidator(Configuration["AzureAd:Authority"]);
                    // todo: move these to Options
                    o.Authority = $"{Configuration["AzureAd:Instance"]}/common/v2.0";
                    o.ClientId = Configuration["AzureAd:ClientId"];
                    o.ClientSecret = Configuration["AzureAd:ClientSecret"];
                    o.CallbackPath = Configuration["AzureAd:CallbackPath"];
                    o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                    o.TokenValidationParameters = new TokenValidationParameters()
                    {
                        IssuerValidator = prefixValidator.Validate
                    };
                })
                .AddOpenIdConnect(AzureAdB2COptions.AuthenticationScheme, o =>
                {
                    // todo: move these to options
                    o.Authority = $"{Configuration["AzureAdB2C:Instance"]}/tfp/{Configuration["AzureAdB2C:Domain"]}/{Configuration["AzureAdB2C:SignUpSignInPolicyId"]}/v2.0";
                    o.ClientId = Configuration["AzureAdB2C:ClientId"];
                    o.ClientSecret = Configuration["AzureAdB2C:ClientSecret"];
                    o.CallbackPath = Configuration["AzureAdB2C:CallbackPath"];
                    //o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                    o.TokenValidationParameters = new TokenValidationParameters()
                    {
                        // b2c has two issuer options per policy
                        ValidIssuers = new List<string>() {
                            $"{Configuration["AzureAdB2C:Instance"]}/{Configuration["AzureAdB2C:TenantId"]}/v2.0/",
                            $"{Configuration["AzureAdB2C:Instance"]}/tfp/{Configuration["AzureAdB2C:TenantId"]}/{Configuration["AzureAdB2C:SignUpSignInPolicyId"]}/v2.0/"
                        }
                    };
                })
                .AddCookie(o =>
                {
                    o.LoginPath = "/auth";
                })
                ;

            // AAD configuration
            services.Configure<OpenIdConnectOptions>(AzureAdOptions.AuthenticationScheme, options =>
            {
                options.Events = new OpenIdConnectEvents()
                {
                    OnAuthorizationCodeReceived = ctx =>
                    {
                        var code = ctx.ProtocolMessage.Code;

                        var app = ConfidentialClientApplicationBuilder
                            .Create(Configuration["AzureAd:ClientId"])
                            .WithClientSecret(Configuration["AzureAd:ClientSecret"])
                            // todo: figure out a better way to do this with IHttpContextAccessor, although it may not matter since we're not dynamically adding redirect uris to AAD
                            .WithRedirectUri($"{Configuration["AzureAd:RedirectUriRoot"]}{Configuration["AzureAd:CallbackPath"]}")
                            .WithAuthority($"{Configuration["AzureAd:Instance"]}/common/v2.0")
                            .Build();

                        try
                        {
                            //todo: cache
                            var result = app.AcquireTokenByAuthorizationCode(new[] { "User.Read" }, code);

                            var tokenRequest = app.AcquireTokenSilent(new[] { "User.Read" }, ctx.Principal.HasClaim(x => x.Type == "preferred_username") ? ctx.Principal.Claims.First(x => x.Type == "preferred_username").Value : ctx.Principal.Claims.First(x => x.Type == "oid").Value);
                            var token = tokenRequest.ExecuteAsync();

                            try
                            {

                            }
                            catch (MsalUiRequiredException ex)
                            {

                                throw;
                            }

                        }
                        catch (Exception)
                        {
                            // todo: something here
                            throw;
                        }

                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        // todo: add any additional claims here, say a database lookup for specific org, tenant, userinfo, etc.
                        // we also want to copy any claims from the AAD ticket
                        //ctx.Principal.AddIdentity(new ClaimsIdentity(ctx.Principal.Claims.ToList()));
                        return Task.CompletedTask;
                    },
                    OnRedirectToIdentityProvider = ctx =>
                    {
                        // todo: modify the prompt here, if necessary - e.g., admin consent
                        return Task.CompletedTask;
                    }
                };
            });

            //B2C configuration
            services.Configure<OpenIdConnectOptions>(AzureAdB2COptions.AuthenticationScheme, x =>
            {
                x.Events = new OpenIdConnectEvents()
                {
                    OnAuthorizationCodeReceived = ctx =>
                    {
                        var code = ctx.ProtocolMessage.Code;

                        var user = ctx.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                        var app = ConfidentialClientApplicationBuilder
                            .Create(Configuration["AzureAd:ClientId"])
                            .WithClientSecret(Configuration["AzureAd:ClientSecret"])
                            .WithRedirectUri(Configuration["AzureAd:RedirectUri"])
                            .WithAuthority($"{Configuration["AzureAd:Instance"]}/{Configuration["AzureAd:Domain"]}/v2.0")
                            .Build();

                        try
                        {
                            // todo: cache
                            var result = app.AcquireTokenByAuthorizationCode(new[] { "User.Read" }, code);
                        }
                        catch (Exception)
                        {
                            // todo: something sane
                            throw;
                        }
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        // todo: add any additional claims here, say a database lookup for specific org, tenant, userinfo, etc.
                        // we also want to copy any claims from the AAD ticket
                        ctx.Principal.AddIdentity(new ClaimsIdentity(ctx.Principal.Claims.ToList()));
                        return Task.CompletedTask;
                    },
                    OnRemoteFailure = ctx =>
                    {
                        // b2c handles things like password reset with an error :/ so we need to capture that and redirect
                        // see https://github.com/aspnet/AspNetCore/blob/master/src/Azure/AzureAD/Authentication.AzureADB2C.UI/src/AzureAdB2COpenIDConnectEventHandlers.cs
                        ctx.HandleResponse();
                        // Handle the error code that Azure Active Directory B2C throws when trying to reset a password from the login page 
                        // because password reset is not supported by a "sign-up or sign-in policy".
                        // Below is a sample error message:
                        // 'access_denied', error_description: 'AADB2C90118: The user has forgotten their password.
                        // Correlation ID: f99deff4-f43b-43cc-b4e7-36141dbaf0a0
                        // Timestamp: 2018-03-05 02:49:35Z
                        //', error_uri: 'error_uri is null'.
                        if (ctx.Failure is OpenIdConnectProtocolException && ctx.Failure.Message.Contains("AADB2C90118"))
                        {
                            // If the user clicked the reset password link, redirect to the reset password route
                            //ctx.Response.Redirect($"{ctx.Request.PathBase}/AzureADB2C/Account/ResetPassword/{SchemeName}");
                        }
                        // Access denied errors happen when a user cancels an action on the Azure Active Directory B2C UI. We just redirect back to
                        // the main page in that case.
                        // Message contains error: 'access_denied', error_description: 'AADB2C90091: The user has cancelled entering self-asserted information.
                        // Correlation ID: d01c8878-0732-4eb2-beb8-da82a57432e0
                        // Timestamp: 2018-03-05 02:56:49Z
                        // ', error_uri: 'error_uri is null'.
                        else if (ctx.Failure is OpenIdConnectProtocolException && ctx.Failure.Message.Contains("access_denied"))
                        {
                            ctx.Response.Redirect($"{ctx.Request.PathBase}/");
                        }
                        else
                        {
                            //ctx.Response.Redirect($"{ctx.Request.PathBase}/AzureADB2C/Account/Error");
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
