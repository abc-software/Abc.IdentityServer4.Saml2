using System.Web;
using System.Web.Mvc;

namespace Mvc5App48.Owin4.Saml2 {
    public class FilterConfig {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters) {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
