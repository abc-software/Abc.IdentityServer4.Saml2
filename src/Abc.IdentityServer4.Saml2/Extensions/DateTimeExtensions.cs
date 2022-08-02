using System;
using System.Diagnostics;

namespace Abc.IdentityServer4.Extensions
{
    internal static class DateTimeExtensions
    {
        [DebuggerStepThrough]
        public static bool InFuture(this DateTime serverTime, DateTime now, int toleranceInSeconds = 10)
        {
            return now.AddSeconds(toleranceInSeconds) < serverTime;
        }

        [DebuggerStepThrough]
        public static bool InPast(this DateTime serverTime, DateTime now, int toleranceInSeconds = 10)
        {
            return now > serverTime.AddSeconds(toleranceInSeconds);
        }
    }
}