using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public sealed class SignInResult
    {
        private static readonly SignInResult _success = new SignInResult { Succeeded = true };
        private static readonly SignInResult _failed = new SignInResult();
        private static readonly SignInResult _lockedOut = new SignInResult { IsLockedOut = true };
        private static readonly SignInResult _twoFactorSuccess = new SignInResult { TwoFactorSignIn = true };

        public bool Succeeded { get; private set; }
        public bool IsLockedOut { get; private set; }
        public bool TwoFactorSignIn { get; private set; }

        public static SignInResult Success => _success;
        public static SignInResult Failed => _failed;
        public static SignInResult LockedOut => _lockedOut;
        public static SignInResult TwoFactorSuccess => _twoFactorSuccess;
    }
}
