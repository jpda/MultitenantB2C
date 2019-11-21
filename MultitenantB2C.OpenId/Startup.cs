using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.Xml;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
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

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpClient();
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o =>
                {
                    o.LoginPath = "/auth";
                })
                .AddOpenIdConnect(AzureAdOptions.AuthenticationScheme, o =>
                {
                    // todo: move these to Options
                    o.Authority = $"{Configuration["AzureAd:Instance"]}/common/v2.0";
                    o.ClientId = Configuration["AzureAd:ClientId"];
                    o.ClientSecret = Configuration["AzureAd:ClientSecret"];
                    o.CallbackPath = Configuration["AzureAd:CallbackPath"];
                    o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                    o.TokenValidationParameters = new TokenValidationParameters()
                    {
                        // move this elsewhere
                        // cache these metadata calls
                        // see https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/blob/master/Microsoft.Identity.Web/Resource/AadIssuerValidator.cs for inspiration
                        // issuer alias data is here: https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint=https://<instance>/common/oauth2/v2.0/authorize&api-version=1.1
                        // v1 issuer alias data is here: https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint=https://<instance>/common/oauth2/authorize&api-version=1.1

                        // if you want to accept _all_ AAD tenants, we need to go get all the issuers from the different endpoints, but they'll all follow a similar pattern, e.g.,
                        // https://sts.windows.net/<tenant-id>
                        // https://login.microsoftonline.com/<tenant-id>
                        // https://login.microsoftonline.com/<tenant-id>/v2.0

                        IssuerValidator = (originalIssuer, token, validationParameters) =>
                        {
                            const string versionedDiscoveryUrl = "https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint={0}common/oauth2{1}authorize&api-version=1.1";

                            // todo: get this from ServiceCollection
                            var a = new System.Net.Http.HttpClient();

                            var validIssuerTemplates = new List<string>();
                            async Task<string> FindIssuers(string instance, string version)
                            {
                                var request = await a.GetAsync(string.Format(versionedDiscoveryUrl, instance, version));
                                var data = JsonDocument.Parse(await request.Content.ReadAsStringAsync());
                                var discoveryUrl = data.RootElement.GetProperty("tenant_discovery_endpoint").GetString();
                                var metadataRequest = await a.GetAsync(discoveryUrl);
                                var metadataData = JsonDocument.Parse(await metadataRequest.Content.ReadAsStringAsync());
                                return metadataData.RootElement.GetProperty("issuer").GetString();
                            }

                            validIssuerTemplates.Add(FindIssuers(Configuration["AzureAd:Instance"], string.Empty).Result);
                            validIssuerTemplates.Add(FindIssuers(Configuration["AzureAd:Instance"], "/v2.0/").Result);

                            // sample issuer: https://login.microsoftonline.com/tenant/v2.0
                            // sample issuer: https://sts.windows.net/tenant

                            var issuerUri = new Uri(originalIssuer);

                            if (token is JwtSecurityToken jwt)
                            {
                                var tokenIssuer = jwt.Claims.SingleOrDefault(x => x.Type == "iss");
                                if (tokenIssuer == null) throw new ArgumentNullException("Issuer missing in token");
                                var tokenIssuerUri = new Uri(tokenIssuer.Value);

                                var tenantClaims = jwt.Claims.Where(x => x.Type == "tid" || x.Type == "tenantId").Select(y => y.Value).Distinct(StringComparer.OrdinalIgnoreCase);
                                if (!tenantClaims.Any()) throw new ArgumentNullException("TenantId or tid claim missing from token");

                                // implies the tenantId and tid claims don't match - this would be weird.
                                if (tenantClaims.Count() > 1) throw new SecurityTokenInvalidIssuerException("Token data error, mulitple tenants");

                                // replace the templates with the actual tenant id
                                // we shouldn't have both tenantId and tid in the same token
                                var validIssuers = validIssuerTemplates.Select(x => x.Replace("{tenantid}", tenantClaims.First()));

                                // if a token's issuer matches the templated issuer from metadata, it's valid so let's move on
                                var matchedIssuers = validIssuers.Where(y => string.Equals(y, tokenIssuer.Value, StringComparison.OrdinalIgnoreCase));
                                if (matchedIssuers.Any())
                                {
                                    return matchedIssuers.First();
                                }
                            }

                            throw new SecurityTokenInvalidIssuerException("No matching issuer found");
                        }
                    };

                })
                .AddOpenIdConnect(AzureAdB2COptions.AuthenticationScheme, o =>
                {
                    // todo: move these to options
                    o.Authority = $"{Configuration["AzureAdB2C:Instance"]}/{Configuration["AzureAdB2C:Domain"]}/{Configuration["AzureAdB2C:SignUpSignInPolicyId"]}/v2.0";
                    o.ClientId = Configuration["AzureAdB2C:ClientId"];
                    o.ClientSecret = Configuration["AzureAdB2C:ClientSecret"];
                    o.CallbackPath = Configuration["AzureAdB2C:CallbackPath"];
                    //o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                })
                // todo: register apps in gov and china
                .AddOpenIdConnect(AzureAdChinaOptions.AuthenticationScheme, o =>
                {
                    // todo: move these to options
                    o.Authority = $"{Configuration["AzureAdB2C:Instance"]}/{Configuration["AzureAdB2C:Domain"]}/{Configuration["AzureAdB2C:SignUpSignInPolicyId"]}/v2.0";
                    o.ClientId = Configuration["AzureAdB2C:ClientId"];
                    o.ClientSecret = Configuration["AzureAdB2C:ClientSecret"];
                    o.CallbackPath = Configuration["AzureAdB2C:CallbackPath"];
                    //o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                })
                .AddOpenIdConnect(AzureAdGovOptions.AuthenticationScheme, o =>
                {
                    // todo: move these to options
                    o.Authority = $"{Configuration["AzureAdB2C:Instance"]}/{Configuration["AzureAdB2C:Domain"]}/{Configuration["AzureAdB2C:SignUpSignInPolicyId"]}/v2.0";
                    o.ClientId = Configuration["AzureAdB2C:ClientId"];
                    o.ClientSecret = Configuration["AzureAdB2C:ClientSecret"];
                    o.CallbackPath = Configuration["AzureAdB2C:CallbackPath"];
                    //o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                })
                ;

            //services.AddTransient<IConfidentialClientApplication>(x =>
            //{
            //    return ConfidentialClientApplicationBuilder
            //            .Create(Configuration["AzureAd:ClientId"])
            //            .WithClientSecret(Configuration["AzureAd:ClientSecret"])
            //            // todo: figure out a better way to do this with IHttpContextAccessor, although it may not matter since we're not dynamically adding redirect uris to AAD
            //            .WithRedirectUri($"{Configuration["AzureAd:RedirectUriRoot"]}{Configuration["AzureAd:CallbackPath"]}")
            //            .WithAuthority($"{Configuration["AzureAd:Instance"]}/{Configuration["AzureAd:Domain"]}/v2.0")
            //            .Build();
            //});

            // AAD configuration
            services.Configure<OpenIdConnectOptions>(AzureAdOptions.AuthenticationScheme, x =>
            {
                x.Events = new OpenIdConnectEvents()
                {
                    OnAuthorizationCodeReceived = ctx =>
                    {
                        var code = ctx.ProtocolMessage.Code;

                        //var user = ctx.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                        var app = ConfidentialClientApplicationBuilder
                            .Create(Configuration["AzureAd:ClientId"])
                            .WithClientSecret(Configuration["AzureAd:ClientSecret"])
                            // todo: figure out a better way to do this with IHttpContextAccessor, although it may not matter since we're not dynamically adding redirect uris to AAD
                            .WithRedirectUri($"{Configuration["AzureAd:RedirectUriRoot"]}{Configuration["AzureAd:CallbackPath"]}")
                            .WithAuthority($"{Configuration["AzureAd:Instance"]}/{Configuration["AzureAd:Domain"]}/v2.0")
                            .Build();

                        try
                        {
                            //todo: cache
                            var result = app.AcquireTokenByAuthorizationCode(new[] { "User.Read" }, code);
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
                        ctx.Principal.AddIdentity(new ClaimsIdentity(ctx.Principal.Claims.ToList()));
                        return Task.CompletedTask;
                    },
                    OnRedirectToIdentityProvider = ctx =>
                    {
                        // todo: modify the prompt here, if necessary - e.g., admin consent
                        return Task.CompletedTask;
                    }
                };
            });

            // B2C configuration
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
                    OnRedirectToIdentityProvider = ctx =>
                    {
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
