namespace System
{
    internal static class StringExtensions
    {
        public static Uri ToUri(this string uriString, UriKind uriKind = UriKind.RelativeOrAbsolute)
        {
            return new Uri(uriString, uriKind);
        }
    }
}