using System;

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
