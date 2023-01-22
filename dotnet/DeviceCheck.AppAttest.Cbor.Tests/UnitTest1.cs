using System;
namespace DeviceCheck.AppAttest.Cbor.Tests;

public class UnitTest1
{
    [Fact]
    public void WhenCborClass_ShouldBeExpectMapKeyType()
    {
        // arrange
        var obj = new TestCbor();

        // act
        var mapKeyType = obj.GetKeyType();

        // assert
        Assert.Equal(typeof(string), mapKeyType);
    }
}


[CborMap]
public partial class TestCbor
{
    [CborProperty("first")]
    public string First { get; set; } = default!;
}