using System;
namespace DeviceCheck.AppAttest.Extensions;

internal static class EnumerableExtensions
{
	public static void Deconstruct<T>(
		this IEnumerable<T> enumerable,
		out T first,
		out IEnumerable<T> rest)
	{
		first = enumerable.First();
		rest = enumerable.Skip(1);
	}

	public static bool TryGetFirst<T>(this IEnumerable<T> values, out T? value)
	{
		var enumerator = values.GetEnumerator();

		if (enumerator.MoveNext())
		{
			value = enumerator.Current;
			return true;
		}

		value = default;
		return false;
	}
}
