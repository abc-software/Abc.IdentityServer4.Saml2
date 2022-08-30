using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Mvc5App48.Owin4.Saml2.Controllers {
    //[Authorize]
    public class HomeController : Controller {
        public ActionResult Index() {
            return View();
        }
    }
}