// ----------------------------------------------------------------------------
// <copyright file="DateTimeExtensions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

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