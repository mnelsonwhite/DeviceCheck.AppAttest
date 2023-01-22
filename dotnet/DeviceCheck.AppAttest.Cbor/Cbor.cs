using System.Formats.Cbor;
using System.Reflection;
using System.Text;

namespace DeviceCheck.AppAttest.Cbor;

public static class Cbor
{
	public static T? Deserialize<T>(
		ReadOnlyMemory<byte> data,
		CborConformanceMode mode = CborConformanceMode.Lax) where T: new()
	{
		var reader = new CborReader(data, mode);
		return GetValue<T>(reader);
	}

	private static T? GetValue<T>(CborReader reader)
	{
		return (T?) GetValue(reader, typeof(T));
	}

	private static object GetMap(
		CborReader reader,
		ICborSerializerContext context,
		object obj)
	{
		var keyType = context.GetKeyType();

		reader.ReadStartMap();
		while(reader.PeekState() != CborReaderState.EndMap)
		{
			var state = reader.PeekState();

			if (state != CborReaderState.TextString)
			{
				throw new InvalidOperationException("Expected map key");
			}

			var key = GetValue(reader, keyType)
				?? throw new InvalidOperationException("Unable to read key");

			if (context.TryGetPropertyType(key, out var type))
			{
				context.SetProperty(key, GetValue(reader, type), obj);
			}
		}

		reader.ReadEndMap();

		return obj;
	}

    private static object? GetMap(CborReader reader, Type type)
	{
		var obj = Activator.CreateInstance(type);

        if (obj is null)
		{
			return null;
		}

		if (obj is ICborSerializerContext context)
		{
			return GetMap(reader, context, obj);
		}

		var properties = type
			.GetProperties(
				BindingFlags.SetProperty |
				BindingFlags.Public |
				BindingFlags.Instance
			)
			.Select(property => {
				var propNameAttr = property.GetCustomAttribute<CborPropertyAttribute>();
				return propNameAttr is null
					? new { Name = (object) property.Name, Property = property }
                    : new { propNameAttr.Name, Property = property };
			})
			.ToDictionary(v => v.Name, v => v.Property);

		var keyType = type.GetCustomAttribute<CborMapAttribute>()?.KeyType ?? typeof(string);

		reader.ReadStartMap();
		while(reader.PeekState() != CborReaderState.EndMap)
		{
			var state = reader.PeekState();

			if (state != CborReaderState.TextString)
			{
				throw new InvalidOperationException("Expected map key");
			}

			var key = GetValue(reader, keyType)
				?? throw new InvalidOperationException("Unable to read key");

            if (properties.TryGetValue(key, out var property))
			{
				property.SetValue(obj, GetValue(reader, property.PropertyType));
            }
        }

		reader.ReadEndMap();
		return obj;
	}

	private static readonly Type _listType = typeof(List<>);
	private static object GetArray(CborReader reader, Type type)
	{
		reader.ReadStartArray();

        var elementType = type.GetElementType()
            ?? throw new InvalidCastException("Cannot get array type");
        var listType = _listType.MakeGenericType(elementType);
		var list = (System.Collections.IList) (
			Activator.CreateInstance(listType)
			?? throw new InvalidOperationException("Cannot create list")
		);

		var isNullable = elementType.IsClass || Nullable.GetUnderlyingType(elementType) != null;

        while (reader.PeekState() != CborReaderState.EndArray)
		{
			var value = GetValue(
				reader,
				elementType
			);

			if (isNullable && value is null)
			{
				list.Add(null);
			}
			else if (value is not null)
			{
                list.Add(value);
            }
		}

		reader.ReadEndArray();

        var array = Array.CreateInstance(elementType, list.Count);
        list.CopyTo(array, 0);

        return array;
	}

	private static byte[] GetIndefiniteLengthByteString(CborReader reader)
	{
        reader.ReadStartIndefiniteLengthByteString();

        using var stream = new MemoryStream();
        Span<byte> buffer = stackalloc byte[200];
            
		while (reader.TryReadByteString(buffer, out var bytesWritten))
		{
			stream.Write(buffer[..bytesWritten]);
        }

		reader.ReadEndIndefiniteLengthByteString();
		return stream.ToArray();
	}

	private static string GetIndefiniteLengthTextString(CborReader reader)
	{
        reader.ReadStartIndefiniteLengthTextString();

        var builder = new StringBuilder();
		Span<char> buffer = stackalloc char[200];

        while (reader.TryReadTextString(buffer, out var bytesWritten))
        {
            builder.Append(buffer[..bytesWritten]);
        }

        reader.ReadEndIndefiniteLengthTextString();
		return builder.ToString();
    }

    private static object? GetValue(CborReader reader, Type type)
	{
		return reader.PeekState() switch
		{
			CborReaderState.TextString when type == typeof(string) => reader.ReadTextString(),
			CborReaderState.Boolean when type == typeof(bool) => reader.ReadBoolean(),
			CborReaderState.ByteString when type == typeof(byte[]) => reader.ReadByteString(),
			CborReaderState.DoublePrecisionFloat when type == typeof(double) => reader.ReadDouble(),
			CborReaderState.HalfPrecisionFloat when type == typeof(Half) => reader.ReadHalf(),
			CborReaderState.NegativeInteger when type == typeof(ulong) => reader.ReadCborNegativeIntegerRepresentation(),
            CborReaderState.NegativeInteger when type == typeof(Int32) => reader.ReadInt32(),
            CborReaderState.NegativeInteger when type == typeof(Int64) => reader.ReadInt64(),
            CborReaderState.Null => () => { reader.ReadNull(); return (object?) null; },
            CborReaderState.SimpleValue when type == typeof(byte) || type == typeof(CborSimpleValue) => reader.ReadSimpleValue(),
            CborReaderState.SinglePrecisionFloat => reader.ReadSingle(),
            CborReaderState.StartArray when type.IsArray => GetArray(reader, type),
            CborReaderState.StartIndefiniteLengthByteString => GetIndefiniteLengthByteString(reader),
            CborReaderState.StartIndefiniteLengthTextString => GetIndefiniteLengthTextString(reader),
            CborReaderState.StartMap => GetMap(reader, type),
            CborReaderState.Tag => reader.ReadTag(),
            CborReaderState.Undefined => null,
            CborReaderState.UnsignedInteger when type == typeof(UInt32) => reader.ReadUInt32(),
            CborReaderState.UnsignedInteger when type == typeof(UInt64) => reader.ReadUInt64(),
            _ => null
		} ;
	}
}
