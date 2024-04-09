using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Lagrange.Core;
using Lagrange.OneBot.Core.Entity.Meta;
using Lagrange.OneBot.Core.Network.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Lagrange.OneBot.Core.Network.Service;

public partial class ForwardWSService(ILogger<ForwardWSService> logger, IOptionsSnapshot<ForwardWSServiceOptions> options, BotContext context) : BackgroundService, ILagrangeWebService
{
    #region Initialization
    private readonly ILogger<ForwardWSService> _logger = logger;
    private readonly ForwardWSServiceOptions _options = options.Value;
    private readonly BotContext _context = context;
    #endregion

    #region Lifecycle
    private readonly HttpListener _listener = new();

    public override Task StartAsync(CancellationToken token)
    {
        string host = _options.Host == "0.0.0.0" ? "*" : _options.Host;

        // First start the HttpListener
        _listener.Prefixes.Add($"http://{host}:{_options.Port}/");
        _listener.Start();

        foreach (string prefix in _listener.Prefixes) Log.LogServerStarted(_logger, prefix);

        // then obtain the HttpListenerContext
        return base.StartAsync(token);
    }

    protected override async Task ExecuteAsync(CancellationToken token)
    {
        try
        {
            while (true) // Looping to Retrieve and Handle HttpListenerContext
            {
                _ = HandleHttpListenerContext(await _listener.GetContextAsync().WaitAsync(token), token);

                token.ThrowIfCancellationRequested();
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.LogWaitConnectException(_logger, e);
        }
    }

    public override async Task StopAsync(CancellationToken token)
    {
        // Stop obtaining the HttpListenerContext first
        await base.StopAsync(token);

        // then stop the HttpListener
        _listener.Stop();
    }
    #endregion

    #region Connect
    private readonly ConcurrentDictionary<string, ConnectionContext> _connection = [];

    private async Task HandleHttpListenerContext(HttpListenerContext context, CancellationToken token)
    {
        // Generating an identifier for this context
        string identifier = Guid.NewGuid().ToString();

        HttpListenerResponse response = context.Response;

        try
        {
            Log.LogConnect(_logger, identifier);

            // Validating AccessToken
            if (!ValidatingAccessToken(context))
            {
                Log.LogValidatingAccessTokenFail(_logger, identifier);

                response.StatusCode = (int)HttpStatusCode.Forbidden;
                response.Close();

                return;
            }

            // Validating whether it is a WebSocket request
            if (!context.Request.IsWebSocketRequest)
            {
                Log.LogNotWebSocketRequest(_logger, identifier);

                response.StatusCode = (int)HttpStatusCode.BadRequest;
                response.Close();

                return;
            }

            // Upgrade to WebSocket
            WebSocketContext wsContext = await context.AcceptWebSocketAsync(null).WaitAsync(token);

            // Building and store ConnectionContext
            CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            _connection.TryAdd(identifier, new(wsContext, cts));

            string path = wsContext.RequestUri.LocalPath;
            bool isApi = path == "/api" || path == "/api/";
            bool isEvent = path == "/event" || path == "/event/";

            // Only API interfaces do not require sending heartbeats
            if (!isApi) _ = HeartbeatAsyncLoop(identifier, cts.Token);

            // The Event interface does not need to receive messages
            // but still needs to receive Close messages to close the connection
            if (isEvent) _ = WaitCloseAsyncLoop(identifier, cts.Token);
            // The Universal interface requires receiving messages
            else _ = ReceiveAsyncLoop(identifier, cts.Token);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.LogHandleHttpListenerContextException(_logger, identifier, e);

            // Attempt to send a 500 response code
            try
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                response.Close();

                return;
            }
            catch { }
        }
    }

    private bool ValidatingAccessToken(HttpListenerContext context)
    {
        // If AccessToken is not configured
        // then allow access unconditionally
        if (string.IsNullOrEmpty(_options.AccessToken)) return true;

        string? token = null;

        // Retrieve the Authorization request header
        string? authorization = context.Request.Headers["Authorization"];
        // If the Authorization request header is not present
        // retrieve the access_token from the QueryString
        if (authorization == null) token = context.Request.QueryString["access_token"];
        // If the Authorization authentication method is Bearer
        // then retrieve the AccessToken
        else if (authorization.StartsWith("Bearer ")) token = authorization["Bearer ".Length..];

        return token == _options.AccessToken;
    }
    #endregion

    #region Receive
    public event EventHandler<MsgRecvEventArgs>? OnMessageReceived;

    public async Task ReceiveAsyncLoop(string identifier, CancellationToken token)
    {
        if (!_connection.TryGetValue(identifier, out ConnectionContext? connection)) return;

        try
        {
            byte[] buffer = new byte[1024];
            while (true)
            {
                int received = 0;
                while (true)
                {
                    ValueTask<ValueWebSocketReceiveResult> resultTask = connection.WsContext.WebSocket
                        .ReceiveAsync(buffer.AsMemory(received), default);

                    ValueWebSocketReceiveResult result = !resultTask.IsCompleted ?
                        await resultTask.AsTask().WaitAsync(token) :
                        resultTask.Result;

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await DisconnectAsync(identifier, WebSocketCloseStatus.NormalClosure, token);
                        return;
                    }

                    received += result.Count;

                    if (result.EndOfMessage) break;

                    if (received == buffer.Length) Array.Resize(ref buffer, buffer.Length << 1);

                    token.ThrowIfCancellationRequested();
                }
                string message = Encoding.UTF8.GetString(buffer.AsSpan(0, received));

                Log.LogReceive(_logger, identifier, message);

                OnMessageReceived?.Invoke(this, new(message, identifier));

                token.ThrowIfCancellationRequested();
            }
        }
        catch (Exception e)
        {
            bool isCanceled = e is OperationCanceledException;

            if (!isCanceled) Log.LogReceiveException(_logger, identifier, e);

            WebSocketCloseStatus status = WebSocketCloseStatus.NormalClosure;
            CancellationToken t = default;
            if (!isCanceled)
            {
                status = WebSocketCloseStatus.InternalServerError;
                t = token;
            }

            await DisconnectAsync(identifier, status, t);

            if (token.IsCancellationRequested) throw;
        }
        finally
        {
            connection.Cts.Cancel();
        }
    }

    public async Task WaitCloseAsyncLoop(string identifier, CancellationToken token)
    {
        if (!_connection.TryGetValue(identifier, out ConnectionContext? connection)) return;

        try
        {
            byte[] buffer = new byte[1024];
            while (true)
            {
                ValueTask<ValueWebSocketReceiveResult> resultTask = connection.WsContext.WebSocket
                        .ReceiveAsync(buffer.AsMemory(), default);

                ValueWebSocketReceiveResult result = !resultTask.IsCompleted ?
                    await resultTask.AsTask().WaitAsync(token) :
                    resultTask.Result;

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await DisconnectAsync(identifier, WebSocketCloseStatus.NormalClosure, token);
                    return;
                }

                token.ThrowIfCancellationRequested();
            }
        }
        catch (Exception e)
        {
            bool isCanceled = e is OperationCanceledException;

            if (!isCanceled) Log.LogWaitCloseException(_logger, identifier, e);

            WebSocketCloseStatus status = WebSocketCloseStatus.NormalClosure;
            CancellationToken t = default;
            if (!isCanceled)
            {
                status = WebSocketCloseStatus.InternalServerError;
                t = token;
            }

            await DisconnectAsync(identifier, status, t);

            if (token.IsCancellationRequested) throw;
        }
        finally
        {
            connection.Cts.Cancel();
        }
    }
    #endregion

    #region Heartbeat
    public async Task HeartbeatAsyncLoop(string identifier, CancellationToken token)
    {
        if (!_connection.TryGetValue(identifier, out ConnectionContext? connection)) return;

        Stopwatch sw = new();
        TimeSpan interval = TimeSpan.FromMilliseconds(_options.HeartBeatInterval);

        try
        {
            // Send ConnectLifecycleMetaEvent
            await SendJsonAsync(
                new OneBotLifecycle(_context.BotUin, "connect"),
                identifier,
                token
            );

            while (true)
            {
                sw.Start();
                // Send HeartbeatMetaEvent
                await SendJsonAsync(
                    new OneBotHeartBeat(
                        _context.BotUin,
                        (int)_options.HeartBeatInterval,
                        new OneBotStatus(true, true)
                    ),
                    identifier,
                    token
                );
                sw.Stop();

                // Implementing precise intervals by subtracting Stopwatch's timing from configured intervals
                await Task.Delay(interval - sw.Elapsed, token);

                sw.Reset();

                token.ThrowIfCancellationRequested();
            }
        }
        catch (Exception e)
        {
            bool isCanceled = e is OperationCanceledException;

            if (!isCanceled) Log.LogHeartbeatException(_logger, identifier, e);

            WebSocketCloseStatus status = WebSocketCloseStatus.NormalClosure;
            CancellationToken t = default;
            if (!isCanceled)
            {
                status = WebSocketCloseStatus.InternalServerError;
                t = token;
            }

            await DisconnectAsync(identifier, status, t);

            if (token.IsCancellationRequested) throw;
        }
        finally
        {
            connection.Cts.Cancel();
        }
    }
    #endregion

    #region Send
    private readonly SemaphoreSlim _sendSemaphoreSlim = new(1);
    public async ValueTask SendJsonAsync<T>(T json, string? identifier = null, CancellationToken token = default)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(json);
        if (identifier != null) await SendBytesAsync(payload, identifier, token);
        else await Task.WhenAll(_connection
            .Where(c =>
            {
                string path = c.Value.WsContext.RequestUri.LocalPath;
                return path != "/api" || path != "/api/";
            })
            .Select(c => SendBytesAsync(payload, c.Key, token))
        );
    }

    public async Task SendBytesAsync(byte[] payload, string identifier, CancellationToken token)
    {
        await _sendSemaphoreSlim.WaitAsync(token);
        try
        {
            if (!_connection.TryGetValue(identifier, out ConnectionContext? connection)) return;

            Log.LogSend(_logger, identifier, payload);
            await connection.WsContext.WebSocket.SendAsync(payload.AsMemory(), WebSocketMessageType.Text, true, token);
        }
        finally
        {
            _sendSemaphoreSlim.Release();
        }
    }
    #endregion

    #region Disconnect
    private async Task DisconnectAsync(string identifier, WebSocketCloseStatus status, CancellationToken token)
    {
        if (!_connection.TryRemove(identifier, out ConnectionContext? connection)) return;

        try
        {
            await connection.WsContext.WebSocket.CloseAsync(status, null, token);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Log.LogDisconnectException(_logger, identifier, e);
        }
        finally
        {
            Log.LogDisconnect(_logger, identifier);
        }
    }
    #endregion

    #region ConnectionContext
    public class ConnectionContext(WebSocketContext context, CancellationTokenSource cts)
    {
        public WebSocketContext WsContext { get; } = context;
        public CancellationTokenSource Cts { get; } = cts;
    }
    #endregion

    #region Log
    public static partial class Log
    {
        #region Normal
        [LoggerMessage(EventId = 10, Level = LogLevel.Information, Message = "The server is started at {prefix}")]
        public static partial void LogServerStarted(ILogger logger, string prefix);

        [LoggerMessage(EventId = 11, Level = LogLevel.Information, Message = "Connect({identifier})")]
        public static partial void LogConnect(ILogger logger, string identifier);

        public static void LogReceive(ILogger logger, string identifier, string payload)
        {
            if (!logger.IsEnabled(LogLevel.Trace)) return;

            if (payload.Length > 1024) payload = $"{payload.AsSpan(0, 1024)} ...{payload.Length - 1024} bytes";

            InnerLogReceive(logger, identifier, payload);
        }

        [LoggerMessage(EventId = 12, Level = LogLevel.Trace, Message = "Receive({identifier}) {payload}", SkipEnabledCheck = true)]
        private static partial void InnerLogReceive(ILogger logger, string identifier, string payload);

        public static void LogSend(ILogger logger, string identifier, byte[] payload)
        {
            if (!logger.IsEnabled(LogLevel.Trace)) return;

            string payloadString = Encoding.UTF8.GetString(payload);

            if (payload.Length > 1024) payloadString = $"{payloadString.AsSpan(0, 1024)} ...{payloadString.Length - 1024} bytes";

            InnerLogSend(logger, identifier, payloadString);
        }

        [LoggerMessage(EventId = 13, Level = LogLevel.Trace, Message = "Send({identifier}) {payload}", SkipEnabledCheck = true)]
        private static partial void InnerLogSend(ILogger logger, string identifier, string payload);

        [LoggerMessage(EventId = 14, Level = LogLevel.Information, Message = "Disconnect({identifier})")]
        public static partial void LogDisconnect(ILogger logger, string identifier);
        #endregion

        #region Exception
        [LoggerMessage(EventId = 992, Level = LogLevel.Error, Message = "LogDisconnectException({identifier})")]
        public static partial void LogDisconnectException(ILogger logger, string identifier, Exception e);

        [LoggerMessage(EventId = 993, Level = LogLevel.Error, Message = "LogHeartbeatException({identifier})")]
        public static partial void LogHeartbeatException(ILogger logger, string identifier, Exception e);

        [LoggerMessage(EventId = 994, Level = LogLevel.Error, Message = "WaitCloseException({identifier})")]
        public static partial void LogWaitCloseException(ILogger logger, string identifier, Exception e);

        [LoggerMessage(EventId = 995, Level = LogLevel.Error, Message = "ReceiveException({identifier})")]
        public static partial void LogReceiveException(ILogger logger, string identifier, Exception e);

        [LoggerMessage(EventId = 996, Level = LogLevel.Warning, Message = "NotWebSocketRequest({identifier})")]
        public static partial void LogNotWebSocketRequest(ILogger logger, string identifier);

        [LoggerMessage(EventId = 997, Level = LogLevel.Warning, Message = "ValidatingAccessTokenFail({identifier})")]
        public static partial void LogValidatingAccessTokenFail(ILogger logger, string identifier);

        [LoggerMessage(EventId = 998, Level = LogLevel.Critical, Message = "HandleHttpListenerContextException({identifier})")]
        public static partial void LogHandleHttpListenerContextException(ILogger logger, string identifier, Exception e);

        [LoggerMessage(EventId = 999, Level = LogLevel.Critical, Message = "WaitConnectException")]
        public static partial void LogWaitConnectException(ILogger logger, Exception e);
        #endregion
    }
    #endregion
}
