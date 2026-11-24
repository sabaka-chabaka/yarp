// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Linq;
using System.Text;
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Yarp.Kubernetes.Tests;

namespace Yarp.Kubernetes.Controller.Certificates.Tests;

public class CertificateHelperTests
{
    private readonly Mock<ILogger<CertificateHelper>> _mockLogger;
    private readonly ICertificateHelper _certificateHelper;
    private readonly byte[] _pemPrivateKey;
    private readonly byte[] _pemCert;
    private readonly byte[] _derPrivateKey;
    private readonly byte[] _derCert;

    public CertificateHelperTests()
    {
        _mockLogger = new Mock<ILogger<CertificateHelper>>();

        _certificateHelper = new CertificateHelper(_mockLogger.Object);

        _pemCert = ReadManifestData(".Certificates.cert.pem");
        _pemPrivateKey = ReadManifestData(".Certificates.key.pem");
        _derCert = ReadManifestData(".Certificates.cert.der");
        _derPrivateKey = ReadManifestData(".Certificates.key.der");
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(false, false, false)]
    public void CertificateConversionFromPem(bool loadCert, bool loadKey, bool expectCert)
    {
        // Arrange
        var cert = loadCert ? _pemCert : (byte[])null;
        var key = loadKey ? _pemPrivateKey : (byte[])null;

        var secret = KubeResourceGenerator.CreateSecret("yarp-ingress-tls", "default", cert, key);
        var namespacedName = NamespacedName.From(secret);

        // Act
        var actualCertificate = _certificateHelper.ConvertCertificate(namespacedName, secret);

        // Assert
        if (expectCert)
        {
            Assert.NotNull(actualCertificate);
        }
        else
        {
            Assert.Null(actualCertificate);
        }
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(false, false, false)]
    public void CertificateConversionFromDer(bool loadCert, bool loadKey, bool expectCert)
    {
        // Arrange
        var cert = loadCert ? _derCert : (byte[])null;
        var key = loadKey ? _derPrivateKey : (byte[])null;

        var secret = KubeResourceGenerator.CreateSecret("yarp-ingress-tls", "default", cert, key);
        var namespacedName = NamespacedName.From(secret);

        // Act
        var actualCertificate = _certificateHelper.ConvertCertificate(namespacedName, secret);

        // Assert
        if (expectCert)
        {
            Assert.NotNull(actualCertificate);
        }
        else
        {
            Assert.Null(actualCertificate);
        }
    }

    [Fact]
    public async Task ConvertedCertificate_CanBeUsedForServerTlsHandshake()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var selfSigned = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var certPem = Encoding.ASCII.GetBytes(selfSigned.ExportCertificatePem());
        var keyPem = Encoding.ASCII.GetBytes(rsa.ExportPkcs8PrivateKeyPem());

        var secret = KubeResourceGenerator.CreateSecret("yarp-ingress-tls", "default", certPem, keyPem);
        var namespacedName = NamespacedName.From(secret);

        using var converted = _certificateHelper.ConvertCertificate(namespacedName, secret);
        Assert.NotNull(converted);
        Assert.True(converted.HasPrivateKey);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            var serverTask = Task.Run(async () =>
            {
                using var serverClient = await listener.AcceptTcpClientAsync(cts.Token);
                using var serverSsl = new SslStream(serverClient.GetStream());
                await serverSsl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions { ServerCertificate = converted },
                    cts.Token);
            });

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
            using var clientSsl = new SslStream(client.GetStream());
            await clientSsl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                },
                cts.Token);

            await serverTask;
            Assert.True(clientSsl.IsAuthenticated);
        }
        finally
        {
            listener.Stop();
        }
    }

    private static byte[] ReadManifestData(string ending)
    {
        var assembly = typeof(CertificateHelperTests).Assembly;
        var resourceName = assembly.GetManifestResourceNames().Single(str => str.EndsWith(ending));
        var manifestStream = assembly.GetManifestResourceStream(resourceName);

        using var reader = new StreamReader(manifestStream);
        return Encoding.UTF8.GetBytes(reader.ReadToEnd());
    }
}
