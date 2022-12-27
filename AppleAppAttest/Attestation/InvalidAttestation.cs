namespace AppleAppAttest.Attestation;

public class InvalidAttestation: ArgumentException
{
    public InvalidAttestation(string argument): base(argument)
    {

    }
}