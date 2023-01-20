using System.Net;

namespace DeviceCheck.AppAttest;

public class SystemClock : IClock
{
    public DateTimeOffset Now => DateTimeOffset.Now;
}
