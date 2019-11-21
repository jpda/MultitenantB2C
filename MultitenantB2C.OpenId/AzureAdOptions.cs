using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MultitenantB2C.OpenId
{
    public class AzureAdOptions
    {
        public const string AuthenticationScheme = "AzureAd";
    }

    public class AzureAdB2COptions
    {
        public const string AuthenticationScheme = "AzureAdB2C";
    }

    public class AzureAdChinaOptions
    {
        public const string AuthenticationScheme = "AzureAdChina";
    }

    public class AzureAdGovOptions
    {
        public const string AuthenticationScheme = "AzureAdGov";
    }

    public class AzureAdGermanyOptions
    {
        public const string AuthenticationScheme = "AzureAdGermany";
    }
}