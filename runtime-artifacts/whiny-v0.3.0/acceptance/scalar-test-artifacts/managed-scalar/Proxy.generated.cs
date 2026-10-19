using System;
using System.Runtime.InteropServices;

internal static class WhinyNative
{
    internal const int Ok = 0;
    internal static readonly byte[] AdapterHash = new byte[] { 0x49, 0x0a, 0xd7, 0x5f, 0xcf, 0x53, 0xf2, 0x82, 0x15, 0xe8, 0x46, 0x47, 0x40, 0xff, 0x7e, 0x59, 0x95, 0xb3, 0x8a, 0x8c, 0xbe, 0xf2, 0xf8, 0xf0, 0x62, 0x6e, 0xf5, 0xa7, 0xec, 0x2c, 0x54, 0x14 };
    static WhinyNative()
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
            int status = WhinyNative.wvb_client_call(
                WhinyNative.AdapterHash, 1u, request, (UIntPtr)request.Length,
                response, (UIntPtr)response.Length, out responseLength);
            if (status != WhinyNative.Ok || responseLength.ToUInt64() != (ulong)response.Length)
                throw new ExternalException("WinAPI VM Bridge call failed", status);
            return BitConverter.ToInt32(response, 0);
        }
    }
}
