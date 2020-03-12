using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MultitenantB2C.SingleHomed.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IAuthenticationSchemeProvider _provider;
        private readonly HttpClient _client;

        public AccountController(IAuthenticationSchemeProvider schemeProvider, IHttpClientFactory c)
        {
            _provider = schemeProvider;
            _client = c.CreateClient();
        }

        public async Task<IActionResult> Index()
        {
            return View(await _provider.GetAllSchemesAsync());
        }

        public IActionResult SignIn(string returnUrl = "/")
        {
            if (User.Identity.IsAuthenticated)
            {
                return Redirect(returnUrl);
            }
            return View();
        }

        [Authorize(AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)]
        public IActionResult SignInB2CLocal()
        {
            return Redirect("/");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> SignOut()
        {
            var schemes = await _provider.GetAllSchemesAsync();
            return this.SignOut(schemes.Select(x => x.Name).ToArray());
        }

        [HttpPost]
        public async Task<IActionResult> HrdRedirect([FromForm]string mail)
        {
            var p = new AuthenticationProperties() { RedirectUri = "/" };
            if (await IsLikelyAad(mail))
            {
                p.SetParameter<string>("login_hint", mail);
                p.SetParameter<string>("domain_hint", "aad");
                return Challenge(p, OpenIdConnectDefaults.AuthenticationScheme);
            }
            p.SetParameter<string>("login_hint", mail);
            return Challenge(p, OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpPost]
        public async Task<IActionResult> HrdSrf([FromForm]string mail)
        {
            return new OkObjectResult(new { Found = await IsLikelyAad(mail) });
        }

        private async Task<bool> IsLikelyAad(string mail)
        {
            var realmRequest = await _client.GetAsync($"https://login.microsoftonline.com/common/UserRealm/{mail}?api-version=2.0");
            if (realmRequest.IsSuccessStatusCode)
            {
                var resp = await System.Text.Json.JsonSerializer.DeserializeAsync<GetUserRealmResponse>(await realmRequest.Content.ReadAsStreamAsync());
                // todo: consider other criteria + b2b
                if (resp.ConsumerDomain) return false;
                if (resp.IsViral) return false;
                switch (resp.NameSpaceType)
                {
                    case "Federated":
                    case "Managed":
                        return true;
                }
            }
            return false;
        }
    }

    public class GetUserRealmSrfResponse
    {
        public int State { get; set; }
        public int UserState { get; set; }
        public string NameSpaceType { get; set; }
    }

    public class GetUserRealmResponse
    {
        public string NameSpaceType { get; set; }
        public bool ConsumerDomain { get; set; }
        public bool IsViral { get; set; }
    }
}
