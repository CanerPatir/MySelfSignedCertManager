using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;

namespace MySelfSignedCertManager
{
    class Program
    {
        private static CreateCertificates _cc;

        // ref: https://damienbod.com/2020/02/10/create-certificates-for-identityserver4-signing-using-net-core/
        static void Main(string[] args)
        {
            var sp = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();
 
            _cc = sp.GetService<CreateCertificates>();
            
            
            var rsaCert = CreateRsaCertificate("localhost", 10);
            var ecdsaCert = CreateECDsaCertificate("localhost", 10);
 
            string password = "1234";
            var iec = sp.GetService<ImportExportCertificate>();
 
            var rsaCertPfxBytes = iec.ExportSelfSignedCertificatePfx(password, rsaCert);
            File.WriteAllBytes("rsaCert.pfx", rsaCertPfxBytes);
 
            var ecdsaCertPfxBytes = iec.ExportSelfSignedCertificatePfx(password, ecdsaCert);
            File.WriteAllBytes("ecdsaCert.pfx", ecdsaCertPfxBytes);
            
            /*
             *usage:1
             *
             *
    var ecdsaCertificate = new X509Certificate2(
    Path.Combine(_environment.ContentRootPath, "ecdsaCert.pfx"), "1234");
    
    ECDsaSecurityKey ecdsaCertificatePublicKey = new ECDsaSecurityKey(ecdsaCertificate.GetECDsaPrivateKey());
 
services.AddIdentityServer()
    .AddSigningCredential(ecdsaCertificatePublicKey, "ES256") 
    .AddInMemoryIdentityResources(Config.GetIdentityResources())
    .AddInMemoryApiResources(Config.GetApiResources())
    .AddInMemoryClients(Config.GetClients())
    .AddAspNetIdentity<ApplicationUser>()
    .AddProfileService<IdentityWithAdditionalClaimsProfileService>();
             *
             * usage: 2
             *
             var rsaCertificate = new X509Certificate2(Path.Combine(_environment.ContentRootPath, "rsaCert.pfx"), "1234");
                 
services.AddIdentityServer()
    .AddSigningCredential(rsaCertificate) // rsaCertificate
    .AddInMemoryIdentityResources(Config.GetIdentityResources())
    .AddInMemoryApiResources(Config.GetApiResources())
    .AddInMemoryClients(Config.GetClients())
    .AddAspNetIdentity<ApplicationUser>()
    .AddProfileService<IdentityWithAdditionalClaimsProfileService>();
             */
        }
        
        public static X509Certificate2 CreateRsaCertificate(string dnsName, int validityPeriodInYears)
        {
            var basicConstraints = new BasicConstraints
            {
                CertificateAuthority = false,
                HasPathLengthConstraint = false,
                PathLengthConstraint = 0,
                Critical = false
            };
 
            var subjectAlternativeName = new SubjectAlternativeName
            {
                DnsName = new List<string>{ dnsName }
            };
 
            var x509KeyUsageFlags = X509KeyUsageFlags.DigitalSignature;
 
            // only if certification authentication is used
            var enhancedKeyUsages = new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.1"),  // TLS Server auth
                new Oid("1.3.6.1.5.5.7.3.2"),  // TLS Client auth
            };
 
            var certificate = _cc.NewRsaSelfSignedCertificate(
                new DistinguishedName { CommonName = dnsName },
                basicConstraints,
                new ValidityPeriod
                {
                    ValidFrom = DateTimeOffset.UtcNow,
                    ValidTo = DateTimeOffset.UtcNow.AddYears(validityPeriodInYears)
                },
                subjectAlternativeName,
                enhancedKeyUsages,
                x509KeyUsageFlags,
                new RsaConfiguration { KeySize = 2048 }
            );
 
            return certificate;
        }
        
        public static X509Certificate2 CreateECDsaCertificate(string dnsName, int validityPeriodInYears)
        {
            var basicConstraints = new BasicConstraints
            {
                CertificateAuthority = false,
                HasPathLengthConstraint = false,
                PathLengthConstraint = 0,
                Critical = false
            };
 
            var san = new SubjectAlternativeName
            {
                DnsName = new List<string>{ dnsName }
            };
 
            var x509KeyUsageFlags = X509KeyUsageFlags.DigitalSignature;
 
            // only if certification authentication is used
            var enhancedKeyUsages = new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.1"),  // TLS Server auth
                new Oid("1.3.6.1.5.5.7.3.2"),  // TLS Client auth
            };
 
            var certificate = _cc.NewECDsaSelfSignedCertificate(
                new DistinguishedName { CommonName = dnsName },
                basicConstraints,
                new ValidityPeriod
                {
                    ValidFrom = DateTimeOffset.UtcNow,
                    ValidTo = DateTimeOffset.UtcNow.AddYears(validityPeriodInYears)
                },
                san,
                enhancedKeyUsages,
                x509KeyUsageFlags,
                new ECDsaConfiguration());
 
            return certificate;
        }

        
    }
    
    
    
    
    
}