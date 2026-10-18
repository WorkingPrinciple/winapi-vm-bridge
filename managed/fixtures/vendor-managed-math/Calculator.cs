namespace Example.ManagedMath;

public static class Calculator
{
    public static int Add(int left, int right) => checked(left + right);
}
