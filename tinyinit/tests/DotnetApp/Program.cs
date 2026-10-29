using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;

if (args[0] == "--network-check")
{
    await Probe.CheckNetworkAsync().ConfigureAwait(false);
    return;
}

var name = args[0];
Probe.CheckData();
await Probe.CheckAspNetAsync().ConfigureAwait(false);
var status = await File.ReadAllTextAsync("/proc/self/status").ConfigureAwait(false);
var uid = status.Split('\n').First(line => line.StartsWith("Uid:", StringComparison.Ordinal)).Split('\t')[1];
var setting = Environment.GetEnvironmentVariable("TINYINIT_TEST_VALUE");
var uptime = await File.ReadAllTextAsync("/proc/uptime").ConfigureAwait(false);
var readyUptimeMs = (double.Parse(uptime.Split(' ')[0], CultureInfo.InvariantCulture) * 1000)
    .ToString("F0", CultureInfo.InvariantCulture);
Console.WriteLine($"app {name}: uid={uid}; config={setting}; cwd={Environment.CurrentDirectory}");
while (true)
{
    await File.WriteAllTextAsync($"/home/app/{name}.txt",
        $"app={name} uid={uid} config={setting} runtime={RuntimeInformation.FrameworkDescription} icu=ok tz=ok trust=ok aspnet=ok ready_uptime_ms={readyUptimeMs}\n").ConfigureAwait(false);
    await Task.Delay(200).ConfigureAwait(false);
}

internal static class Probe
{
    internal static async Task CheckNetworkAsync()
    {
        var addresses = await Dns.GetHostAddressesAsync("www.microsoft.com").ConfigureAwait(false);
        if (addresses.Length == 0)
        {
            throw new InvalidOperationException("DNS returned no addresses");
        }

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
        using var response = await client.GetAsync("https://www.microsoft.com/").ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        Console.WriteLine($"DNS_HTTPS_OK addresses={addresses.Length}");
    }

    internal static void CheckData()
    {
        var culture = CultureInfo.GetCultureInfo("fr-FR");
        if (1234.5m.ToString("F1", culture) != "1234,5")
        {
            throw new InvalidOperationException("ICU culture formatting failed");
        }

        var zone = TimeZoneInfo.FindSystemTimeZoneById("America/Los_Angeles");
        var summer = zone.GetUtcOffset(new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero));
        var winter = zone.GetUtcOffset(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        if (summer != TimeSpan.FromHours(-7) || winter != TimeSpan.FromHours(-8))
        {
            throw new InvalidOperationException("timezone transitions failed");
        }

        using var roots = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        roots.Open(OpenFlags.ReadOnly);
        if (roots.Certificates.Count == 0)
        {
            throw new InvalidOperationException("no trusted root certificates");
        }
    }

    internal static async Task CheckAspNetAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        await using (app.ConfigureAwait(false))
        {
            app.MapGet("/", () => Results.Text("ASPNET_OK"));
            await app.StartAsync().ConfigureAwait(false);
            using var client = new HttpClient();
            var body = await client.GetStringAsync(app.Urls.Single()).ConfigureAwait(false);
            if (body != "ASPNET_OK")
            {
                throw new InvalidOperationException("ASP.NET loopback request failed");
            }
        }
    }
}
