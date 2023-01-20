[AttributeUsage(AttributeTargets.Property)]
public class CborPropertyAttribute: Attribute
{
	public readonly object Name;

	public CborPropertyAttribute(object name)
	{
		Name = name;
	}
}
