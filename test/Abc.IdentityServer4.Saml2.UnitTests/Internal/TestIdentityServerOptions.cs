namespace IdentityServer4.Configuration
{
    internal class TestIdentityServerOptions
    {
        public static IdentityServerOptions Create()
        {
            var options = new IdentityServerOptions
            {
                IssuerUri = "https://idsvr.com"
            };

            return options;
        }
    }
}
