using System.Diagnostics.CodeAnalysis;
namespace DeviceCheck.AppAttest.Cbor;

public interface ICborSerializerContext
{
    Type GetKeyType();
    void SetProperty(object property, object? value, object instance);
    bool TryGetPropertyType(object property, [NotNullWhen(returnValue:true)] out Type? type);
}