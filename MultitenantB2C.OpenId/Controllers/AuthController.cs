using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MultitenantB2C.OpenId.Controllers
{
    public class AuthController : Controller
    {
        private readonly IAuthenticationSchemeProvider _provider;

        public AuthController(IAuthenticationSchemeProvider schemeProvider)
        {
            _provider = schemeProvider;
        }

        [AllowAnonymous]
        public async Task<IActionResult> Index()
        {
            return View(await _provider.GetAllSchemesAsync());
        }

        [Authorize(AuthenticationSchemes = AzureAdOptions.AuthenticationScheme)]
        public IActionResult AzureAd()
        {
            return Redirect("/");
        }

        [Authorize(AuthenticationSchemes = AzureAdB2COptions.AuthenticationScheme)]
        public IActionResult AzureAdB2C()
        {
            return Redirect("/");
        }

        public async Task<IActionResult> SignOut()
        {
            var schemes = await _provider.GetAllSchemesAsync();
            return this.SignOut(schemes.Select(x => x.Name).ToArray());
        }
    }
}