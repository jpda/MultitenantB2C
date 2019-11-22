using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.Tasks;

namespace MultitenantB2C.OpenId
{
    public class AzureAdTenantIssuerPrefixValidator : TokenIssuerValidator
    {
        private readonly List<string> _validPrefixes = new List<string>();

        public AzureAdTenantIssuerPrefixValidator(IEnumerable<string> validPrefixes)
        {
            _validPrefixes.AddRange(validPrefixes);
        }

        public AzureAdTenantIssuerPrefixValidator(string validPrefix) : this(new List<string>() { validPrefix }) { }

        public string Validate(string originalIssuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            var tokenIssuer = GetTokenIssuer(token);
            var tokenTenant = GetTokenTenant(token);

            // if any issuers are added manually, we don't want to ignore them
            if (validationParameters.ValidIssuers != null && validationParameters.ValidIssuers.Any())
            {
                _validPrefixes.AddRange(validationParameters.ValidIssuers);
            }

            // replace the templates with the actual tenant id

            var validIssuerList = _validPrefixes.Where(y => y != null).Select(x => x.Replace("{tenantid}", tokenTenant));

            // if a token's issuer matches the templated issuer from metadata, it's valid so let's move on
            var matchedIssuers = validIssuerList.Where(validIssuer => string.Equals(validIssuer, tokenIssuer, StringComparison.OrdinalIgnoreCase));
            if (matchedIssuers.Any())
            {
                return matchedIssuers.First();
            }

            if (_validPrefixes.Contains(tokenIssuer, StringComparer.OrdinalIgnoreCase))
            {
                return tokenIssuer;
            }

            throw new SecurityTokenInvalidIssuerException("No valid issuer found");
        }
    }

    public abstract class TokenIssuerValidator
    {
        //public abstract IEnumerable<string> GetValidIssuerList();

        protected static string GetTokenIssuer(SecurityToken token)
        {
            var tokenIssuer = string.Empty;

            if (token is JwtSecurityToken jwt)
            {
                var tokenIssuerClaim = jwt.Claims.SingleOrDefault(x => x.Type == "iss");
                if (tokenIssuerClaim == null) throw new ArgumentNullException("iss claim missing in token");

                tokenIssuer = tokenIssuerClaim.Value;
            }
            else if (token is JsonWebToken webToken)
            {
                if (webToken.TryGetPayloadValue<string>("iss", out tokenIssuer))
                {
                    throw new SecurityTokenInvalidIssuerException("iss claim missing in token");
                }
            }

            return tokenIssuer;
        }

        protected static string GetTokenTenant(SecurityToken token)
        {
            var tokenTenants = new List<string>();

            if (token is JwtSecurityToken jwt)
            {
                var tenantClaims = jwt.Claims.Where(x => x.Type == "tid" || x.Type == "tenantid").Select(y => y.Value).Distinct(StringComparer.OrdinalIgnoreCase);
                tokenTenants.AddRange(tenantClaims);

            }
            else if (token is JsonWebToken webToken)
            {
                if (webToken.TryGetPayloadValue<string>("tid", out string tid))
                {
                    tokenTenants.Add(tid);
                }
                if (webToken.TryGetPayloadValue<string>("tenantid", out string tenantid))
                {
                    tokenTenants.Add(tenantid);
                }
            }

            if (!tokenTenants.Any()) throw new ArgumentNullException("tenantid or tid claim missing from token");

            // implies the tenantid and tid claims don't match - this would be weird.
            if (tokenTenants.Count() > 1) throw new SecurityTokenInvalidIssuerException("Token data error, tenant data mismatch");

            var tenantId = tokenTenants.Single();

            return tenantId;
        }
    }


    public class AzureAdTenantIssuerValidator : TokenIssuerValidator
    {
        private readonly HttpClient _client;
        private readonly string _aadInstance = "https://login.microsoftonline.com/";
        private const string VersionedDiscoveryUrl = "https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint={0}common/oauth2{1}authorize&api-version=1.1";
        private readonly bool _failOnRetrievalError;

        // cache these metadata calls
        // see https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/blob/master/Microsoft.Identity.Web/Resource/AadIssuerValidator.cs for inspiration
        // issuer alias data is here: https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint=https://<instance>/common/oauth2/v2.0/authorize&api-version=1.1
        // v1 issuer alias data is here: https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint=https://<instance>/common/oauth2/authorize&api-version=1.1

        public AzureAdTenantIssuerValidator(HttpClient client, string azureAdInstance, bool failOnRetrievalError = false)
        {
            _client = client;
            _aadInstance = azureAdInstance;
            _failOnRetrievalError = failOnRetrievalError;
        }

        public string Validate(string originalIssuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            var validIssuerList = new List<string>();

            var tokenIssuer = GetTokenIssuer(token);
            var tokenTenant = GetTokenTenant(token);

            // if any issuers are added manually, we don't want to ignore them
            if (validationParameters.ValidIssuers != null && validationParameters.ValidIssuers.Any())
            {
                validIssuerList.AddRange(validationParameters.ValidIssuers);
            }

            // if the issuer matches a manually provided one, shortcut out of here
            if (validIssuerList.Contains(tokenIssuer, StringComparer.OrdinalIgnoreCase))
            {
                return tokenIssuer;
            }

            var validIssuerTemplates = new List<string>
            {
                FindIssuersByInstance(_aadInstance, string.Empty).Result,
                FindIssuersByInstance(_aadInstance, "/v2.0/").Result
            };

            // replace the templates with the actual tenant id
            validIssuerList.AddRange(validIssuerTemplates.Select(x => x.Replace("{tenantid}", tokenTenant)));

            // if a token's issuer matches the templated issuer from metadata, it's valid so let's move on
            var matchedIssuers = validIssuerList.Where(validIssuer => string.Equals(validIssuer, tokenIssuer, StringComparison.OrdinalIgnoreCase));
            if (matchedIssuers.Any())
            {
                return matchedIssuers.First();
            }

            throw new SecurityTokenInvalidIssuerException("No matching issuer found");
        }

        private async Task<string> FindIssuersByInstance(string instance, string version)
        {
            try
            {
                var request = await _client.GetAsync(string.Format(VersionedDiscoveryUrl, instance, version));

                if (_failOnRetrievalError)
                {
                    request.EnsureSuccessStatusCode();
                }

                var data = JsonDocument.Parse(await request.Content.ReadAsStringAsync());
                var discoveryUrl = data.RootElement.GetProperty("tenant_discovery_endpoint").GetString();
                var metadataRequest = await _client.GetAsync(discoveryUrl);
                var metadataData = JsonDocument.Parse(await metadataRequest.Content.ReadAsStringAsync());
                return metadataData.RootElement.GetProperty("issuer").GetString();
            }
            catch (Exception)
            {
                if (_failOnRetrievalError) throw;
                // otherwise, return an empty string - this could be a case of a proxy or other outbound restriction on a web server, etc.
                return string.Empty;
            }
        }

    }
}
