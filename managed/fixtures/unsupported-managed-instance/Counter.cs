namespace Unsupported.ManagedInstance;

public sealed class Counter
{
    public int Increment(int value) => checked(value + 1);
}
