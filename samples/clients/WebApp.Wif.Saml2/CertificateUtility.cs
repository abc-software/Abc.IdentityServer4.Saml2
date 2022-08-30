//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
//-----------------------------------------------------------------------------

using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Samples.Saml.Utilities
{
    /// <summary>
    /// The <c>CertificateUtility</c> class provides hardcoded certificates for use in the samples.
    /// </summary>
    class CertificateUtility
    {
        #region KeyInfo clauses
        /*
         The service provider signing token:
         
         <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>
           MIIDdjCCAl6gAwIBAgIQB6jA/2z5Y7pHPCT/JgNPBTANBgkqhkiG9w0BAQQFADA
           9MTswOQYDVQQDEzJXSUYgU2FtcGxlcyAtIFNlcnZpY2UgUHJvdmlkZXIgU2lnbm
           luZyBDZXJ0aWZpY2F0ZTAeFw0xMDEwMDIwMDI2MDlaFw0zNjAxMDEwNzAwMDBaM
           D0xOzA5BgNVBAMTMldJRiBTYW1wbGVzIC0gU2VydmljZSBQcm92aWRlciBTaWdu
           aW5nIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE
           Ava0dWCUP/NpqUpkxN92Hupf8Qi03Md2yebAnU9kl26fhvsQmL/paYWKkZ/Ghm3
           sLGkl1YpPdCvr3g1uNglOzB3fS2legYAYqxVvYxpBJrm8g7f7ZfY39mHtxkWuWV
           izERE7jLPBbgX2nake/UilU5WviPgHjwK4jHn+Ho0lVmCVyVsOjNYQrS3bPUno1
           krEYrnF7F+MVQQKpWRODaTnXz3i3mLElqni/kgsYCXVxqV5bCmqlQxV03jD3pRf
           Tf1dgbxMJEme+doZNf8KaKKoRH1t27yIYkRTVJEn6R6lwxbkWCJHZ5jsMWffNxO
           nN9HxW34L5j+ERQaH+2iKhGt+g5QIDAQABo3IwcDBuBgNVHQEEZzBlgBDRveN2i
           BZdZuNHANqpnuN5oT8wPTE7MDkGA1UEAxMyV0lGIFNhbXBsZXMgLSBTZXJ2aWNl
           IFByb3ZpZGVyIFNpZ25pbmcgQ2VydGlmaWNhdGWCEAeowP9s+WO6Rzwk/yYDTwU
           wDQYJKoZIhvcNAQEEBQADggEBADBp0bhjpKG3Dk3sTl8sFXAbl7q1Q6cVChrwFg
           g8buQc4FRV06K4y3EBY060FMBfEjS0eE4rpUEajiVLaZ+8KA+5AN+q5a00J/hxL
           Vy8CTplxZxtCxPiZqBHw3YT7g+/QWBNiEAXd4y5CY0Wa1CqW0SayMmIZxG2o/uR
           cL7O307DX4k35V96bdnhNTRYtfUdqBpwsiuwGNW9ND297cgThEPZzqjPMpTsoYT
           pLQAHUN9Uv4IsfjcQB+nnHniWSEz7SQl2cBtSz7QCaGLkheYnDEd5y6eYWM+G3+
           rIwc6y3cBVZiMvIasdu0jGighpozanq2/wkr/J1jgEC9UHvN9w9Sk=
                    </X509Certificate>
                </X509Data>
            </KeyInfo>
          
            The identity provider signing token:

         <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>
            MIIDeTCCAmGgAwIBAgIQ/wlFjD9vP5lCPfHJw9ItrjANBgkqhkiG9w0BAQQFADA+
            MTwwOgYDVQQDEzNXSUYgU2FtcGxlcyAtIElkZW50aXR5IFByb3ZpZGVyIFNpZ25p
            bmcgQ2VydGlmaWNhdGUwHhcNMTAxMDAyMDAyNTUzWhcNMzYwMTAxMDcwMDAwWjA+
            MTwwOgYDVQQDEzNXSUYgU2FtcGxlcyAtIElkZW50aXR5IFByb3ZpZGVyIFNpZ25p
            bmcgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr
            dbl6TLqCnhNFJu2L+3ZQp8DKFVjikHoqtBOJ2QwtCcO2kGUF19KWtf9J1yf4nZBk
            NP6rhPfZ9KGjiZp+6akO3G0ilqDzHdcG4U+0EgPSqNIpfl3XMfvNxMeDwHUgDxVB
            qIBbYoAJdTXI3A2sJHXN0H28SA+yu+RpJ5m6DL91LmTv6TiOcU4SFNkjATLI7TfZ
            SJLlwpx7m8S0UAdE4ispqj6jdqfIJ9pCEZHIOgVSgvVo8SctYtMXfs0NDHACguI9
            PlLtEpVCoW8YpjZzZs1PCE7a/pa71rJLRtmEqY8IDjaGEr1p1hzJTBe5E58+qglj
            iErRmKaIgzS1tbGsVDoNAgMBAAGjczBxMG8GA1UdAQRoMGaAEMVKWIqPO/YYDH2P
            bz9dT4uhQDA+MTwwOgYDVQQDEzNXSUYgU2FtcGxlcyAtIElkZW50aXR5IFByb3Zp
            ZGVyIFNpZ25pbmcgQ2VydGlmaWNhdGWCEP8JRYw/bz+ZQj3xycPSLa4wDQYJKoZI
            hvcNAQEEBQADggEBAJvfDujQ8ANw+EyXqSfnK8t+46yoTd0tztMvl5ZJ+b7u+i/f
            i+bqAPR7jveW0qGu/QM7Gi9DeL8W3muefCeTEpZA46SayaaYIrlEg3BTfrucy6Ys
            eLK8nRvPI+Y8BWKGwC3RzfZgJNAY3ACusLH1bFNNo8SIxHe1txPqHGnSVp10u6Hs
            ZF+hv84aLSiA95n83ullsGMYoDgL0nJ3jfe7faldGIdhtD7HmLiFdxb+Kc5OtzgY
            LOae1DIjti4fT4fTCpve4UCFjgJL9ONYVD2rD/U1bZ8FwxrPFs29IOZ7T+iXOp0t
            haqIhfJV2Pb7FEck/v3EEb0MKFU/rx7DebiovJE=
                    </X509Certificate>
                </X509Data>
            </KeyInfo>
         */

        #endregion

        #region Raw certificates
        const string IdentityProviderSigningCertificate
    = @"MIIDeTCCAmGgAwIBAgIQ/wlFjD9vP5lCPfHJw9ItrjANBgkqhkiG9w0BAQQFADA+MTwwOgYDVQQDEzNXSUYgU2FtcGxlcyAtIElkZW50aXR5IFByb3ZpZGVyIFNpZ25pbmcgQ2VydGlmaWNhdGUwHhcNMTAxMDAyMDAyNTUzWhcNMzYwMTAxMDcwMDAwWjA+MTwwOgYDVQQDEzNXSUYgU2FtcGxlcyAtIElkZW50aXR5IFByb3ZpZGVyIFNpZ25pbmcgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrdbl6TLqCnhNFJu2L+3ZQp8DKFVjikHoqtBOJ2QwtCcO2kGUF19KWtf9J1yf4nZBkNP6rhPfZ9KGjiZp+6akO3G0ilqDzHdcG4U+0EgPSqNIpfl3XMfvNxMeDwHUgDxVBqIBbYoAJdTXI3A2sJHXN0H28SA+yu+RpJ5m6DL91LmTv6TiOcU4SFNkjATLI7TfZSJLlwpx7m8S0UAdE4ispqj6jdqfIJ9pCEZHIOgVSgvVo8SctYtMXfs0NDHACguI9PlLtEpVCoW8YpjZzZs1PCE7a/pa71rJLRtmEqY8IDjaGEr1p1hzJTBe5E58+qgljiErRmKaIgzS1tbGsVDoNAgMBAAGjczBxMG8GA1UdAQRoMGaAEMVKWIqPO/YYDH2Pbz9dT4uhQDA+MTwwOgYDVQQDEzNXSUYgU2FtcGxlcyAtIElkZW50aXR5IFByb3ZpZGVyIFNpZ25pbmcgQ2VydGlmaWNhdGWCEP8JRYw/bz+ZQj3xycPSLa4wDQYJKoZIhvcNAQEEBQADggEBAJvfDujQ8ANw+EyXqSfnK8t+46yoTd0tztMvl5ZJ+b7u+i/fi+bqAPR7jveW0qGu/QM7Gi9DeL8W3muefCeTEpZA46SayaaYIrlEg3BTfrucy6YseLK8nRvPI+Y8BWKGwC3RzfZgJNAY3ACusLH1bFNNo8SIxHe1txPqHGnSVp10u6HsZF+hv84aLSiA95n83ullsGMYoDgL0nJ3jfe7faldGIdhtD7HmLiFdxb+Kc5OtzgYLOae1DIjti4fT4fTCpve4UCFjgJL9ONYVD2rD/U1bZ8FwxrPFs29IOZ7T+iXOp0thaqIhfJV2Pb7FEck/v3EEb0MKFU/rx7DebiovJE=";

        const string IdentityProviderSigningCertificateWithPrivateKey
    = @"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";

        const string ServiceProviderSigningCertificate
            = @"MIIDdjCCAl6gAwIBAgIQB6jA/2z5Y7pHPCT/JgNPBTANBgkqhkiG9w0BAQQFADA9MTswOQYDVQQDEzJXSUYgU2FtcGxlcyAtIFNlcnZpY2UgUHJvdmlkZXIgU2lnbmluZyBDZXJ0aWZpY2F0ZTAeFw0xMDEwMDIwMDI2MDlaFw0zNjAxMDEwNzAwMDBaMD0xOzA5BgNVBAMTMldJRiBTYW1wbGVzIC0gU2VydmljZSBQcm92aWRlciBTaWduaW5nIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAva0dWCUP/NpqUpkxN92Hupf8Qi03Md2yebAnU9kl26fhvsQmL/paYWKkZ/Ghm3sLGkl1YpPdCvr3g1uNglOzB3fS2legYAYqxVvYxpBJrm8g7f7ZfY39mHtxkWuWVizERE7jLPBbgX2nake/UilU5WviPgHjwK4jHn+Ho0lVmCVyVsOjNYQrS3bPUno1krEYrnF7F+MVQQKpWRODaTnXz3i3mLElqni/kgsYCXVxqV5bCmqlQxV03jD3pRfTf1dgbxMJEme+doZNf8KaKKoRH1t27yIYkRTVJEn6R6lwxbkWCJHZ5jsMWffNxOnN9HxW34L5j+ERQaH+2iKhGt+g5QIDAQABo3IwcDBuBgNVHQEEZzBlgBDRveN2iBZdZuNHANqpnuN5oT8wPTE7MDkGA1UEAxMyV0lGIFNhbXBsZXMgLSBTZXJ2aWNlIFByb3ZpZGVyIFNpZ25pbmcgQ2VydGlmaWNhdGWCEAeowP9s+WO6Rzwk/yYDTwUwDQYJKoZIhvcNAQEEBQADggEBADBp0bhjpKG3Dk3sTl8sFXAbl7q1Q6cVChrwFgg8buQc4FRV06K4y3EBY060FMBfEjS0eE4rpUEajiVLaZ+8KA+5AN+q5a00J/hxLVy8CTplxZxtCxPiZqBHw3YT7g+/QWBNiEAXd4y5CY0Wa1CqW0SayMmIZxG2o/uRcL7O307DX4k35V96bdnhNTRYtfUdqBpwsiuwGNW9ND297cgThEPZzqjPMpTsoYTpLQAHUN9Uv4IsfjcQB+nnHniWSEz7SQl2cBtSz7QCaGLkheYnDEd5y6eYWM+G3+rIwc6y3cBVZiMvIasdu0jGighpozanq2/wkr/J1jgEC9UHvN9w9Sk=";

        const string ServiceProviderSigningCertificateWithPrivateKey
    = @"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";
        #endregion

        /// <summary>
        /// Returns an X509SecurityToken representing the signing token
        /// of the identity provider.
        /// </summary>
        /// <param name="includePrivateKey">Specifies whether to include private key in resulting token.</param>                
        /// <returns>The signing token of the identity provider.</returns>
        public static SecurityToken GetIdentityProviderSigningToken( bool includePrivateKey )
        {
            X509Certificate2 certificate = null;

            if ( includePrivateKey )
            {
                certificate = new X509Certificate2(
                    Convert.FromBase64String( IdentityProviderSigningCertificateWithPrivateKey ), String.Empty, X509KeyStorageFlags.PersistKeySet );
            }
            else
            {
                certificate = new X509Certificate2(
                    Convert.FromBase64String( IdentityProviderSigningCertificate ) );
            }

            return new X509SecurityToken( certificate );
        }

        /// <summary>
        /// Returns an X509SecurityToken representing the signing token
        /// of the service provider.
        /// </summary>
        /// <param name="includePrivateKey">Specifies whether to include private key in resulting token.</param>        
        /// <returns>The signing token of the service provider.</returns>
        public static SecurityToken GetServiceProviderSigningToken( bool includePrivateKey )
        {
            X509Certificate2 certificate = null;

            if ( includePrivateKey )
            {
                certificate = new X509Certificate2(
                    Convert.FromBase64String( ServiceProviderSigningCertificateWithPrivateKey ), String.Empty, X509KeyStorageFlags.PersistKeySet );
            }
            else
            {
                certificate = new X509Certificate2(
                    Convert.FromBase64String( ServiceProviderSigningCertificate ) );
            }

            return new X509SecurityToken( certificate );
        }
    }
}
