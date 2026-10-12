using FileInspectorX.Web;

if (args.Length > 0 && args[0] == "--worker") return Worker.Run(args);
var port = 5088;
var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FileInspectorX", "local-reports");
for (var index = 0; index < args.Length; index += 2)
{
    if (index + 1 >= args.Length) throw new ArgumentException("Options require a value: --Port <port> --DataDirectory <path>.");
    switch (args[index])
    {
        case "--Port": port = int.Parse(args[index + 1], System.Globalization.CultureInfo.InvariantCulture); break;
        case "--DataDirectory": dataRoot = args[index + 1]; break;
        default: throw new ArgumentException("Unknown option: " + args[index]);
    }
}
if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Cancel(); };
using var catalog = new Catalog(Path.GetFullPath(dataRoot));
await LocalServer.Run(port, catalog, shutdown.Token);
return 0;
