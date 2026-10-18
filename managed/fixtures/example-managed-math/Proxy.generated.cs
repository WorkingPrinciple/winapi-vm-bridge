using System;
using System.Runtime.InteropServices;

internal static class WvbNative
{
    internal const int Ok = 0;
    internal static readonly byte[] AdapterHash = new byte[] { 0x39, 0xbe, 0x15, 0x5b, 0x3a, 0x60, 0xa7, 0x46, 0x21, 0xbb, 0xa8, 0x91, 0xd1, 0x2d, 0x2f, 0xb1, 0x2d, 0xaa, 0xe9, 0x94, 0xf5, 0xaa, 0x0d, 0xbc, 0x7b, 0xcf, 0x73, 0x2f, 0x43, 0x5c, 0xa9, 0xc2 };
    static WvbNative()
    {
        if (!BitConverter.IsLittleEndian)
            throw new PlatformNotSupportedException("WinAPI VM Bridge scalar encoding requires little-endian Windows");
    }
    [DllImport("wvb_client_ffi", EntryPoint = "wvb_client_call", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int wvb_client_call(
        byte[] adapterHash, uint operationId,
        byte[] request, UIntPtr requestLength,
        [Out] byte[] response, UIntPtr responseCapacity,
        out UIntPtr responseLength);
}

namespace @Example.@ManagedMath
{
    public static partial class @Calculator
    {
        public static int @Add(int @left, int @right)
        {
            byte[] request = new byte[8];
            BitConverter.GetBytes(@left).CopyTo(request, 0);
            BitConverter.GetBytes(@right).CopyTo(request, 4);
            byte[] response = new byte[4];
            UIntPtr responseLength;
            int status = WvbNative.wvb_client_call(
                WvbNative.AdapterHash, 1u, request, (UIntPtr)request.Length,
                response, (UIntPtr)response.Length, out responseLength);
            if (status != WvbNative.Ok || responseLength.ToUInt64() != (ulong)response.Length)
                throw new ExternalException("WinAPI VM Bridge call failed", status);
            return BitConverter.ToInt32(response, 0);
        }
    }
}
