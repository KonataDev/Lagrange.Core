using System.Text;
using System.Text.Json;
using Lagrange.Core;
using Lagrange.Core.Common.Interface.Api;
using Lagrange.Core.Event.EventArg;
using Lagrange.Core.Utility.Extension;
using Lagrange.Core.Utility.Sign;
using Lagrange.OneBot.Core.Network;
using Lagrange.OneBot.Core.Notify;
using Lagrange.OneBot.Core.Operation;
using Lagrange.OneBot.Message;
using Lagrange.OneBot.Utility;
using LiteDB;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using JsonSerializer = System.Text.Json.JsonSerializer;
using LogLevel = Lagrange.Core.Event.EventArg.LogLevel;

namespace Lagrange.OneBot;

public class LagrangeApp : IHost
{
    private readonly IHost _hostApp;
    
    public IServiceProvider Services => _hostApp.Services;

    public ILogger<LagrangeApp> Logger { get; }
    
    public IConfiguration Configuration => Services.GetRequiredService<IConfiguration>();
    
    public BotContext Instance => Services.GetRequiredService<BotContext>();
    
    public LagrangeWebSvcCollection WebService => Services.GetRequiredService<LagrangeWebSvcCollection>();

    public MessageService MessageService { get; set; }
    
    public OperationService OperationService { get; set; }

    private bool _isFirstLogin;
    
    internal LagrangeApp(IHost host)
    {
        _hostApp = host;
        Logger = Services.GetRequiredService<ILogger<LagrangeApp>>();

        Services.GetRequiredService<MusicSigner>();
        MessageService = Services.GetRequiredService<MessageService>();
        OperationService = Services.GetRequiredService<OperationService>();

        _isFirstLogin = true;
    }

    public async Task StartAsync(CancellationToken cancellationToken = new())
    {
        await _hostApp.StartAsync(cancellationToken);
        Logger.LogInformation("Lagrange.OneBot Implementation has started");
        Logger.LogInformation($"Protocol: {Configuration["Protocol"]} | {Instance.ContextCollection.AppInfo.CurrentVersion}");

        Instance.ContextCollection.Packet.SignProvider = Services.GetRequiredService<SignProvider>();
        if (!string.IsNullOrEmpty(Configuration["Account:Password"]))
            Instance.ContextCollection.Keystore.PasswordMd5 = await Encoding.UTF8.GetBytes(Configuration["Account:Password"] ?? "").Md5Async();

        Instance.Invoker.OnBotLogEvent += (_, args) => Services.GetRequiredService<ILogger<BotContext>>().Log(args.Level switch
        {
            LogLevel.Debug => Microsoft.Extensions.Logging.LogLevel.Trace,
            LogLevel.Verbose => Microsoft.Extensions.Logging.LogLevel.Information,
            LogLevel.Information => Microsoft.Extensions.Logging.LogLevel.Information,
            LogLevel.Warning => Microsoft.Extensions.Logging.LogLevel.Warning,
            LogLevel.Fatal => Microsoft.Extensions.Logging.LogLevel.Error,
            _ => Microsoft.Extensions.Logging.LogLevel.Error
        }, args.ToString());

        Instance.Invoker.OnBotOnlineEvent += async (_, args) =>
        {
            if (args.Reason == BotOnlineEvent.OnlineReason.Reconnect && !_isFirstLogin) return;
            
            var keystore = Instance.UpdateKeystore();
            Logger.LogInformation($"Bot Online: {keystore.Uin}");
            string json = JsonSerializer.Serialize(keystore, new JsonSerializerOptions { WriteIndented = true });
            
            // Adapters should be started here instead of at the start of application
            await WebService.StartAsync(cancellationToken);
            Services.GetRequiredService<NotifyService>().RegisterEvents();
            
            await File.WriteAllTextAsync(Configuration["ConfigPath:Keystore"] ?? "keystore.json", json, cancellationToken);

            _isFirstLogin = false;
        };
        
        if (string.IsNullOrEmpty(Configuration["Account:Password"]) &&
            Instance.ContextCollection.Keystore.Session.TempPassword == null) // EasyLogin and PasswordLogin is both disabled
        {
            Logger.LogInformation("Session expired or Password not filled in, try to login by QrCode");

            if (await Instance.FetchQrCode() is { } qrCode)
            {
                QrCodeHelper.Output(qrCode.Url ?? "", Configuration.GetValue<bool>("QrCode:ConsoleCompatibilityMode"));
                await File.WriteAllBytesAsync($"qr-{Instance.BotUin}.png", qrCode.QrCode ?? Array.Empty<byte>(), cancellationToken);
                
                _ = Task.Run(Instance.LoginByQrCode, cancellationToken);
            }
        }
        else
        {
            Instance.Invoker.OnBotCaptchaEvent += async (_, args) =>
            {
                Logger.LogWarning($"Captcha: {args.Url}");
                Logger.LogWarning("Please input ticket and randomString:");

                await Task.Run(() =>
                {
                    var ticket = Console.ReadLine();
                    var randomString = Console.ReadLine();

                    if (ticket != null && randomString != null) Instance.SubmitCaptcha(ticket, randomString);
                }, cancellationToken);
            };

            _ = Task.Run(Instance.LoginByPassword, cancellationToken);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = new())
    {
        Logger.LogInformation("Lagrange.OneBot Implementation has stopped");
        
        Instance.Dispose();

        Services.GetRequiredService<LiteDatabase>().Dispose();
        await WebService.StopAsync(cancellationToken);
        await _hostApp.StopAsync(cancellationToken);
    }
    
    public void Dispose()
    {
        _hostApp.Dispose();
        GC.SuppressFinalize(this);
    }
}