using Lagrange.Core.Internal.Event;

namespace Lagrange.Core.Common.Interface.Api;

public static class BotExt
{
    /// <summary>
    /// Fetch the qrcode for QRCode Login
    /// </summary>
    /// <returns>the byte of QRCode, usually in the form of PNG</returns>
    public static async Task<byte[]?> FetchQrCode(this BotContext bot)
        => await bot.ContextCollection.Business.WtExchangeLogic.FetchQrCode();
    
    /// <summary>
    /// Use this method to login by QrCode, you should call <see cref="FetchQrCode"/> first
    /// </summary>
    public static Task LoginByQrCode(this BotContext bot)
        => bot.ContextCollection.Business.WtExchangeLogic.LoginByQrCode();
    
    /// <summary>
    /// Use this method to login by password, EasyLogin may be preformed if there is sig in <see cref="BotKeystore"/>
    /// </summary>
    public static async Task<bool> LoginByPassword(this BotContext bot)
        => await bot.ContextCollection.Business.WtExchangeLogic.LoginByPassword();
    
    /// <summary>
    /// Submit the captcha of the url given by the <see cref="EventInvoker.OnBotCaptchaEvent"/>
    /// </summary>
    /// <returns>Whether the captcha is submitted successfully</returns>
    public static bool SubmitCaptcha(this BotContext bot, string ticket, string randStr)
        => bot.ContextCollection.Business.WtExchangeLogic.SubmitCaptcha(ticket, randStr);
    
    /// <summary>
    /// Use this method to update keystore, so EasyLogin may be preformed next time by using this keystore
    /// </summary>
    /// <returns>BotKeystore instance</returns>
    public static BotKeystore UpdateKeystore(this BotContext bot)
        => bot.ContextCollection.Keystore;
}