using System;
using Whiny.Generated;

byte[] request = new byte[8];
BitConverter.GetBytes(20).CopyTo(request, 0);
BitConverter.GetBytes(22).CopyTo(request, 4);
byte[] response = new byte[4];

int status = ManagedDispatcher.Dispatch(1, request, response, out int responseLength);
if (status != ManagedDispatcher.Ok
    || responseLength != 4
    || BitConverter.ToInt32(response, 0) != 42)
{
    throw new InvalidOperationException(
        $"managed dispatch failed: status={status} length={responseLength}");
}

if (ManagedDispatcher.Dispatch(1, new byte[7], response, out _) !=
    ManagedDispatcher.InvalidBuffer)
{
    throw new InvalidOperationException("invalid request length was accepted");
}

if (ManagedDispatcher.Dispatch(999, request, response, out _) !=
    ManagedDispatcher.OperationUnknown)
{
    throw new InvalidOperationException("unknown operation was accepted");
}

BitConverter.GetBytes(int.MaxValue).CopyTo(request, 0);
BitConverter.GetBytes(1).CopyTo(request, 4);
if (ManagedDispatcher.Dispatch(1, request, response, out _) !=
    ManagedDispatcher.InvocationFailed)
{
    throw new InvalidOperationException("target exception was not contained");
}

Console.WriteLine("managed-dispatch-oracle=ok result=42");
