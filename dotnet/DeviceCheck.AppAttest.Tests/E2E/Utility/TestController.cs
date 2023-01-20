using DeviceCheck.AppAttest.Attestation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DeviceCheck.AppAttest.Tests.E2E.Utility;

[Route("/test")]
[Authorize(AuthenticationSchemes = AppAttestDefaults.AuthenticationScheme)]
public class TestController
{
	public TestController()
	{

	}

	[HttpGet]
	public string Get()
	{
		return "test";
	}

	[HttpPost]
	public string Post([FromBody]TestModel value)
	{
		return value.Value;
	}

	public class TestModel
	{
		public string Value { get; set; } = default!;
	}
}
