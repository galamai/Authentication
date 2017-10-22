using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public static class SignInConstants
    {
        private static readonly string CookiePrefix = "SignIn";

        public static readonly string ApplicationScheme = CookiePrefix + ".Application";
        public static readonly string ExternalScheme = CookiePrefix + ".External";
        public static readonly string TwoFactorRememberMeScheme = CookiePrefix + ".TwoFactorRememberMe";
        public static readonly string TwoFactorUserIdScheme = CookiePrefix + ".TwoFactorUserId";
    }
}
