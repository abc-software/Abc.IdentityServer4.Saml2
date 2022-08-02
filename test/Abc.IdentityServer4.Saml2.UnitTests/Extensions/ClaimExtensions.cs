namespace System.Security.Claims
{
    internal static class ClaimExtensions
    {
        public static Claim AddProperty(this Claim claim, string property, string value)
        {
            claim.Properties[property] = value;
            return claim;
        }
    }
}
