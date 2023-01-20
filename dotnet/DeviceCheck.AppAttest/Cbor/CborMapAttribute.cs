namespace DeviceCheck.AppAttest.Cbor;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
public class CborMapAttribute: Attribute
{
	public readonly Type KeyType;

	public CborMapAttribute(Type keyType)
	{
		KeyType = keyType;
    }
}
