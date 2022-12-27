using System.Net;

namespace AppleAppAttest;

public class SystemClock : IClock
{
    public DateTimeOffset Now => DateTimeOffset.Now;
}
