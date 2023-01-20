namespace DeviceCheck.AppAttest;

public interface IClock
{
    DateTimeOffset Now { get; }
}
