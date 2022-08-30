using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Linq;

namespace AspNetCore.Saml2
{
    public class Startup {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            services.AddRazorPages();

            services.Configure<Saml2Configuration>(saml2Configuration => {
                saml2Configuration.Issuer = Configuration["saml2:issuer"];
                saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);
                saml2Configuration.SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                saml2Configuration.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.ChainTrust;
                // !!! REMOVE for production
                saml2Configuration.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                // !!! for TEST only
                saml2Configuration.SaveBootstrapContext = true;

                var entityDescriptor = new EntityDescriptor();
                entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Configuration["saml2:metadata"]));
                if (entityDescriptor.IdPSsoDescriptor != null) {
                    saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                    saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                    saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                }
                else {
                    throw new Exception("IdPSsoDescriptor not loaded from metadata.");
                }

                // !!! for ADFS
                saml2Configuration.SignAuthnRequest = true;

                var certPath = Path.Combine(Directory.GetCurrentDirectory(), "saml2.sample.pfx");
                if (!File.Exists(certPath)) {
                    throw new InvalidOperationException($"{certPath} not found");
                }

                saml2Configuration.SigningCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, "abc", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet);

            });

            services.AddSaml2();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            }
            else {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSaml2();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapRazorPages();

                //SAML
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                //END SAML
            });
        }
    }
}
