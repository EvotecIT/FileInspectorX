using System.Net;
using System.Text.Json;

namespace FileInspectorX.Web;

internal sealed record WebResponse(int Status, object? Value = null, string? FilePath = null, string ContentType = "application/json")
{
    internal static WebResponse Json(int status, object? value) => new(status, value);
    internal static WebResponse File(string path, string type) => new(200, FilePath: path, ContentType: type);
}

internal static class LocalServer
{
    internal static async Task Run(int port, Catalog catalog, ContentReaderProfile profile, CancellationToken token)
    {
        using var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
        listener.Start();
        var access = new LocalAccess();
        Console.WriteLine("FileInspectorX local reports: http://127.0.0.1:" + port + "/#token=" + access.Token);
        using var capacity = new SemaphoreSlim(16);
        var requests = new List<Task>();
        var worker = new AnalysisQueue(catalog, profile).RunAsync(token);
        try
        {
            while (!token.IsCancellationRequested)
            {
                await capacity.WaitAsync(token);
                HttpListenerContext context;
                try { context = await listener.GetContextAsync().WaitAsync(token); }
                catch { capacity.Release(); throw; }
                requests.RemoveAll(t => t.IsCompleted);
                requests.Add(Handle(context, port, catalog, access, token).ContinueWith(_ => capacity.Release(), CancellationToken.None));
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally
        {
            listener.Stop();
            await Task.WhenAll(requests);
            try { await worker; } catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        }
    }

    private static async Task Handle(HttpListenerContext context, int port, Catalog catalog, LocalAccess access, CancellationToken token)
    {
        var response = context.Response;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        // Managed HttpListener body reads can remain pending after their token is
        // canceled. Abort the connection to release the read, upload gate and handler.
        using var abort = timeout.Token.Register(static state => AbortResponse((HttpListenerResponse)state!), response);
        try
        {
            timeout.Token.ThrowIfCancellationRequested();
            // Abort may flush the current headers on some backends. Until routing
            // succeeds, a prematurely closed request must not look successful.
            response.StatusCode = 500;
            response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
            response.Headers["X-Content-Type-Options"] = "nosniff";
            response.Headers["Referrer-Policy"] = "no-referrer";
            response.Headers["Cache-Control"] = "no-store";
            var result = await Route(context.Request, port, catalog, access, timeout.Token);
            timeout.Token.ThrowIfCancellationRequested();
            // Rejected bodies may still be unread. Explicitly close their transport
            // instead of leaving HTTP.sys or the managed listener to drain/reuse it.
            if (result.Status >= 400 && context.Request.HasEntityBody) response.KeepAlive = false;
            response.StatusCode = result.Status;
            response.ContentType = result.ContentType;
            if (result.Status == 204 || context.Request.HttpMethod == "HEAD") return;
            var data = result.FilePath == null ? JsonSerializer.SerializeToUtf8Bytes(result.Value, ReportJson.Options) : await System.IO.File.ReadAllBytesAsync(result.FilePath, timeout.Token);
            response.ContentLength64 = data.Length;
            await response.OutputStream.WriteAsync(data, timeout.Token);
        }
        catch (Exception ex) when (timeout.IsCancellationRequested && ex is (OperationCanceledException or IOException or HttpListenerException or ObjectDisposedException))
        { Console.Error.WriteLine("Local request canceled (" + ex.GetType().Name + ")."); }
        catch (Exception ex) when (ex is IOException or HttpListenerException or ObjectDisposedException)
        {
            AbortResponse(response);
            Console.Error.WriteLine("Local request failed (" + ex.GetType().Name + ").");
        }
        finally
        {
            try { response.Close(); }
            catch (Exception ex) when (ex is IOException or HttpListenerException or ObjectDisposedException) { AbortResponse(response); }
        }
    }

    private static void AbortResponse(HttpListenerResponse response)
    {
        // Cancellation callbacks must remain safe when completion/Stop has already
        // closed the response; teardown failures cannot escape the timer callback.
        try { response.Abort(); }
        catch (Exception ex) when (ex is IOException or HttpListenerException or ObjectDisposedException) { }
    }

    private static async Task<WebResponse> Route(HttpListenerRequest request, int port, Catalog catalog, LocalAccess access, CancellationToken token)
    {
        var url = request.Url!;
        if (url.Host != "127.0.0.1" || url.Port != port) return WebResponse.Json(400, new { error = "Invalid host." });
        var method = request.HttpMethod;
        var path = url.AbsolutePath;
        if (path.StartsWith("/api/", StringComparison.Ordinal) && !access.Allows(request.Headers["Authorization"]))
            return WebResponse.Json(403, new { error = "Open the private link printed by the application to access local reports." });
        if (method is not "GET" and not "HEAD")
        {
            if (request.Headers["X-FileInspector-Client"] != "local") return WebResponse.Json(403, new { error = "A local client header is required." });
            var origin = request.Headers["Origin"];
            if (origin != null && (!Uri.TryCreate(origin, UriKind.Absolute, out var source) || source.Scheme != "http" || source.Host != url.Host || source.Port != port))
                return WebResponse.Json(403, new { error = "Cross-origin requests are not allowed." });
        }
        if (method is "GET" or "HEAD")
        {
            var asset = path switch { "/" or "/index.html" => ("index.html", "text/html; charset=utf-8"), "/app.js" => ("app.js", "text/javascript; charset=utf-8"), "/app.css" => ("app.css", "text/css; charset=utf-8"), _ => default };
            if (asset.Item1 != null) return WebResponse.File(Path.Combine(AppContext.BaseDirectory, "wwwroot", asset.Item1), asset.Item2);
            if (path == "/api/reports") return WebResponse.Json(200, catalog.List(request.QueryString["q"]));
            if (path.StartsWith("/api/hash/", StringComparison.Ordinal))
            {
                var hash = path.Substring("/api/hash/".Length);
                return hash.Length == 64 && hash.All(Uri.IsHexDigit) ? WebResponse.Json(200, catalog.ListByHash(hash)) : WebResponse.Json(400, new { error = "A SHA-256 hex value is required." });
            }
        }
        if (path.StartsWith("/api/reports/", StringComparison.Ordinal))
        {
            var pieces = path.Substring("/api/reports/".Length).Split('/');
            if (pieces.Length == 1 && method == "DELETE") return catalog.Delete(pieces[0]);
            if (method is "GET" or "HEAD")
            {
                if (pieces.Length == 1) return catalog.ReportResponse(pieces[0]);
                if (pieces.Length == 2 && pieces[1] == "similar") return catalog.Similar(pieces[0]);
            }
        }
        if (path == "/api/uploads" && method == "POST")
        {
            var name = request.Headers["X-File-Name"] ?? string.Empty;
            if (request.Headers["X-File-Name-Encoded"] == "uri") name = Uri.UnescapeDataString(name);
            try
            {
                if (request.ContentLength64 > Catalog.MaxUploadBytes) return WebResponse.Json(413, new { error = "The upload exceeds 64 MiB." });
                return WebResponse.Json(202, await catalog.Upload(request.InputStream, name, token));
            }
            catch (InvalidDataException ex) { return WebResponse.Json(400, new { error = ex.Message }); }
            catch (CatalogFullException) { return WebResponse.Json(409, new { error = "The local catalog or queue is full. Delete completed reports before uploading more files." }); }
        }
        return WebResponse.Json(404, new { error = "Resource not found." });
    }
}
