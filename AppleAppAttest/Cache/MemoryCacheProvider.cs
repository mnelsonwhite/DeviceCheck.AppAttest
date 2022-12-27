using System.Diagnostics.CodeAnalysis;
using System.Runtime.Caching;


namespace AppleAppAttest.Cache;

public class MemoryCacheProvider : ICacheProvider
{
    private readonly IClock _clock;
    private MemoryCache _cache;

    public MemoryCacheProvider(IClock clock)
	{
        _cache = new MemoryCache("Common.MemoryCacheProvider");
        _clock = clock;
    }

    public Task<T?> Get<T>(string key) where T : notnull
    {
        if (_cache.Get(key) is T t && t is not null)
        {
            return Task.FromResult((T?)t);
        }

        return Task.FromResult(default(T?));
    }

    public Task Remove(string key)
    {
        _cache.Remove(key);
        return Task.CompletedTask;
    }

    public Task Set<T>(string key, T value, TimeSpan ttl) where T : notnull
    {
        _cache.Set(key, value, _clock.Now + ttl);
        return Task.CompletedTask;
    }
}
