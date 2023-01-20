namespace DeviceCheck.AppAttest.Extensions;

internal static class MemoryExtensions
{
    public static bool EquivalentTo(this Memory<byte> value, Memory<byte> to)
    {
        if (value.Length != to.Length) return false;

        for (int i = 0; i < value.Length; i++)
        {
            if (value.Span[i] != to.Span[i]) return false;
        }

        return true;
    }
}