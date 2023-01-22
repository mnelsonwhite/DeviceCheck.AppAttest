using System;
namespace DeviceCheck.AppAttest.Cbor.Tests;

public class CborDeserializerContextGeneratorTests
{
    [Fact]
    public void WhenCborClass_GetKeyType_ShouldBeExpected()
    {
        // arrange
        var obj = new TestCbor();

        // act
        var mapKeyType = obj.GetKeyType();

        // assert
        Assert.Equal(typeof(string), mapKeyType);
    }

    [Fact]
    public void WhenCborClass_TryGetPropertyType_ShouldBeExpected()
    {
        // arrange
        var obj = new TestCbor();

        // act
        var canGet = obj.TryGetPropertyType("first", out var type);

        // assert
        Assert.True(canGet);
        Assert.Equal(typeof(string), type);
    }

    [Fact]
    public void WhenCborClass_SetProperty_ShoudlBeExpected()
    {
        // arrange
        var obj = new TestCbor();

        // act
        obj.SetProperty("first", "test", obj);

        // assert
        Assert.Equal("test", obj.First);
    }
}


[CborMap]
public partial class TestCbor
{
    [CborProperty("first")]
    public string First { get; set; } = default!;
}