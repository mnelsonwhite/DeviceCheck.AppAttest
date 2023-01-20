namespace DeviceCheck.AppAttest.Attestation;

internal class DataBuilder : IDisposable
{
    private readonly MemoryStream _stream;
    private bool disposed = false;

    public DataBuilder()
    {
        _stream = new MemoryStream();
    }

    public DataBuilder Add(ReadOnlySpan<byte> data)
    {
        _stream.Write(data);
        return this;
    }

    public DataBuilder Add(byte[] data)
    {
        _stream.Write(data);
        return this;
    }

    public DataBuilder Add(Memory<byte> data)
    {
        _stream.Write(data.Span);
        return this;
    }

    public DataBuilder Add(Stream data)
    {
        data.CopyTo(_stream);
        return this;
    }

    public byte[] Build()
    {
        var array = _stream.ToArray();
        Dispose();
        return array;
    }

    public void Dispose()
    {
        if (!disposed)
        {
            _stream.Dispose();
        }
    }
}