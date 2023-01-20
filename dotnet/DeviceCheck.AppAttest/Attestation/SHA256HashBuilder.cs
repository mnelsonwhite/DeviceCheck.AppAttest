
using System.Security.Cryptography;

namespace DeviceCheck.AppAttest.Attestation;

internal class SHA256HashBuilder : IDisposable
{
    private readonly MemoryStream _stream;

    public SHA256HashBuilder()
    {
        _stream = new MemoryStream();
    }

    public SHA256HashBuilder Add(ReadOnlySpan<byte> data)
    {
        _stream.Write(data);
        return this;
    }

    public SHA256HashBuilder Add(byte[] data)
    {
        _stream.Write(data);
        return this;
    }

    public SHA256HashBuilder Add(Memory<byte> data)
    {
        _stream.Write(data.Span);
        return this;
    }

    public SHA256HashBuilder Add(Stream data)
    {
        data.CopyTo(_stream);
        return this;
    }

    public ValueTask<byte[]> Build()
    {
        _stream.Seek(0, SeekOrigin.Begin);
        var hash = SHA256.HashDataAsync(_stream);
        Dispose();
        return hash;
    }

    public void Dispose()
    {
        _stream.Dispose();
    }
}
