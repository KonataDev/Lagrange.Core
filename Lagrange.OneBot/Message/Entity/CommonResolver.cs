namespace Lagrange.OneBot.Message.Entity;

public static class CommonResolver
{
    private static readonly HttpClient Client = new();

    public static byte[]? Resolve(string url)
    {
        Uri uri = new(url);

        return uri.Scheme switch
        {
            "http" or "https" => Client.GetAsync(uri).Result.Content.ReadAsByteArrayAsync().Result,
            "file" => File.ReadAllBytes(Path.GetFullPath(uri.AbsolutePath)),
            "base64" => Convert.FromBase64String(url.Replace("base64://", "")),
            _ => null,
        };
    }

    public static Stream? ResolveStream(string url)
    {
        Uri uri = new(url);

        return uri.Scheme switch
        {
            "http" or "https" => Client.GetAsync(uri).Result.Content.ReadAsStreamAsync().Result,
            "file" => new FileStream(Path.GetFullPath(uri.AbsolutePath), FileMode.Open),
            "base64" => new MemoryStream(Convert.FromBase64String(url.Replace("base64://", ""))),
            _ => null,
        };
    }
}
