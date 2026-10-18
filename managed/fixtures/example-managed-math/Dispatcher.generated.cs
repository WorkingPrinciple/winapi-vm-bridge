using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wvb.Generated
{
    public static class ManagedDispatcher
    {
        public const int Ok = 0;
        public const int InvalidBuffer = 1;
        public const int OperationUnknown = 2;
        public const int InvocationFailed = 3;
        static ManagedDispatcher()
        {
            if (!BitConverter.IsLittleEndian)
                throw new PlatformNotSupportedException("WinAPI VM Bridge scalar encoding requires little-endian Windows");
        }
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        public static unsafe int DispatchUnmanaged(
            uint operationId, byte* request, nuint requestLength,
            byte* response, nuint responseCapacity, nuint* responseLength)
        {
            if (responseLength is null
                || response is null
                || (request is null && requestLength != 0)
                || requestLength > int.MaxValue
                || responseCapacity > int.MaxValue)
                return InvalidBuffer;
            *responseLength = 0;
            try
            {
                byte[] managedRequest = new byte[(int)requestLength];
                if (managedRequest.Length != 0)
                    Marshal.Copy((IntPtr)request, managedRequest, 0, managedRequest.Length);
                byte[] managedResponse = new byte[(int)responseCapacity];
                int status = Dispatch(
                    operationId, managedRequest, managedResponse, out int managedLength);
                if (managedLength < 0 || managedLength > managedResponse.Length)
                    return InvocationFailed;
                if (managedLength != 0)
                    Marshal.Copy(managedResponse, 0, (IntPtr)response, managedLength);
                *responseLength = (nuint)managedLength;
                return status;
            }
            catch
            {
                return InvocationFailed;
            }
        }
        public static int Dispatch(
            uint operationId, byte[] request, byte[] response, out int responseLength)
        {
            responseLength = 0;
            if (request is null || response is null)
                return InvalidBuffer;
            switch (operationId)
            {
                case 1u:
                {
                    if (request.Length != 8 || response.Length < 4)
                        return InvalidBuffer;
                    int argument0 = BitConverter.ToInt32(request, 0);
                    int argument1 = BitConverter.ToInt32(request, 4);
                    try
                    {
                        int result = global::@Example.@ManagedMath.@Calculator.@Add(argument0, argument1);
                        BitConverter.GetBytes(result).CopyTo(response, 0);
                        responseLength = 4;
                        return Ok;
                    }
                    catch
                    {
                        return InvocationFailed;
                    }
                }
                default:
                    return OperationUnknown;
            }
        }
    }
}
