namespace AppleAppAttest;

public interface IClock
{
    DateTimeOffset Now { get; }
}
