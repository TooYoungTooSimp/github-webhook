using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var hookPath = builder.Configuration["HookPath"]!;
var bindUrl = builder.Configuration["Listen"]!;
var secret = builder.Configuration["Secret"]!;
var command = builder.Configuration["Command"]!;

SemaphoreSlim _semaphore = new(1, 1);

app.MapPost($"/{hookPath}", async (HttpRequest req, HttpResponse res, ILogger<Program> logger) =>
{
    string delivery = req.Headers["X-GitHub-Delivery"]!;
    string eventName = req.Headers["X-GitHub-Event"]!;
    logger.LogInformation("EventID: {delivery} {eventName}", delivery, eventName);

    string payload;
    string dataToSign;
    if (req.HasFormContentType)
    {
        var form = await req.ReadFormAsync();
        if (form.ContainsKey("payload"))
        {
            payload = form["payload"]!;
        }
        else if (req.Query.ContainsKey("payload"))
        {
            payload = req.Query["payload"]!;
        }
        else
        {
            payload = "";
        }
        dataToSign = "payload=" + WebUtility.UrlEncode(payload);
    }
    else
    {
        using (var reader = new StreamReader(req.Body, Encoding.UTF8))
        {
            payload = await reader.ReadToEndAsync();
        }
        dataToSign = payload;
    }
    string localSig;
    using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secret)))
    {
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
        localSig = "sha1=" + BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
    string remoteSig = req.Headers["X-Hub-Signature"]!;

    logger.LogInformation("Local-Signature: {localSig}", localSig);
    logger.LogInformation("X-Hub-Signature: {remoteSig}", remoteSig);

    if ((string.IsNullOrEmpty(secret) && string.IsNullOrEmpty(remoteSig)) || remoteSig == localSig)
    {
        res.StatusCode = 200;
        res.ContentType = "text/plain";
        _ = ExecuteCallbackAsync(command, payload, logger);
        await res.WriteAsync("triggered");
    }
    else
    {
        logger.LogError("Signature not match");
        res.StatusCode = 401;
    }
});

app.Run(bindUrl);

async Task ExecuteCallbackAsync(string command, string payload, ILogger logger)
{
    await _semaphore.WaitAsync();
    try
    {
        var psi = new ProcessStartInfo
        {
            UseShellExecute = true
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            psi.FileName = "cmd.exe";
            psi.Arguments = $"/c {command}";
        }
        else
        {
            psi.FileName = "/bin/bash";
            psi.Arguments = $"-c \"{command}\"";
        }

        Process.Start(psi);
    }
    catch (Exception ex)
    {
        logger.LogError("Error executing command: {Ex}", ex);
    }
    finally
    {
        _semaphore.Release();
    }
}
