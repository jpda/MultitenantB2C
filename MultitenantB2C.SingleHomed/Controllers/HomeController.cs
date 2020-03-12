using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MultitenantB2C.SingleHomed.Models;

namespace MultitenantB2C.SingleHomed.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private Dictionary<string, string> _orgs;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
            _orgs = new Dictionary<string, string>();
            _orgs.Add("https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0", "Microsoft Corp");
            _orgs.Add("https://login.microsoftonline.com/98a34a88-7940-40e8-af71-913452037f31/v2.0", "jpd.ms Corp");
            _orgs.Add("https://login.microsoftonline.com/55193a41-5b56-4f8a-913a-20087af59ae9/v2.0", "East US 3 Corp");
        }

        //https://login.microsoftonline.com/55193a41-5b56-4f8a-913a-20087af59ae9/v2.0
        public IActionResult Index()
        {
            var idp = User.Claims.FirstOrDefault(x => x.Type == "http://schemas.microsoft.com/identity/claims/identityprovider");

            ViewBag.Idp = idp == null ? "none" : idp.Value;
            ViewBag.KnownOrg = false;

            if (idp == null)
            {
                ViewBag.Org = "indie";
            }
            else
            {
                ViewBag.Org = _orgs.Any(x => x.Key == idp.Value) ? _orgs.First(x => x.Key == idp.Value).Value : "unknown";
                ViewBag.KnownOrg = _orgs.Any(x => x.Key == idp.Value);
            }
            return View();
        }

        [Authorize(Roles = "Artisan")]
        public IActionResult Artisan()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
