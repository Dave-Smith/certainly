// See https://aka.ms/new-console-template for more information

using System.Security.Cryptography.X509Certificates;
using System.Text;

var certsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Certainly");
var certsFilePath = Path.Combine(certsDir, "certainly.pem");
Environment.SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", certsFilePath, EnvironmentVariableTarget.User);

var certsContent = ExportCertificates();
if(!File.Exists(certsFilePath))
{
    Directory.CreateDirectory(certsDir);
    File.Create(certsFilePath).Close();
}
File.WriteAllText(certsFilePath, certsContent);

string ExportCertificates(params string[] friendlyNames)
{
    var sb = new StringBuilder();
    var storeCerts = GetLocalMachineCertificates().Where(c => c.Issuer == c.Subject);
    var certs = friendlyNames.Length == 0
        ? storeCerts.ToList()
        : storeCerts.Where(cert => friendlyNames.Any(name => cert.FriendlyName.Equals(name)));

    Console.WriteLine("Exporting local computer certificates...");
    foreach (var cert in certs)
    {
        Console.WriteLine($"Subject: {cert.Subject}, Issuer: {cert.Issuer}, Friendly Name: {cert.FriendlyName}");
        var content = Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks);
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(content);
        sb.AppendLine("-----END CERTIFICATE-----");
    }

    return sb.ToString();
}

static X509Certificate2Collection GetLocalMachineCertificates()
{
    var localMachineStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
    localMachineStore.Open(OpenFlags.ReadOnly);
    var certificates = localMachineStore.Certificates;
    localMachineStore.Close();
    return certificates;
}