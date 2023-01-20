namespace DeviceCheck.AppAttest.Cache;

public interface ICacheProvider
{
	Task Set<T>(string key, T value, TimeSpan ttl) where T: notnull;
    Task<T?> Get<T>(string key) where T: notnull;
    Task Remove(string key);
}
