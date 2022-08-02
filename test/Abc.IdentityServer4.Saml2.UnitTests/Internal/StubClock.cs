using System;

namespace Microsoft.AspNetCore.Authentication
{
    internal class StubClock : ISystemClock
    {
        public Func<DateTime> UtcNowFunc = () => DateTime.UtcNow;
        public DateTimeOffset UtcNow => new DateTimeOffset(UtcNowFunc());
    }
}