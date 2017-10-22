using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class PhoneNumberTokenProvider : TotpSecurityStampBasedTokenProvider
    {
        public override bool CanGenerateTwoFactorToken(ISignIn signIn) =>
            signIn is ISignInSupportsPhoneNumber supportsPhoneNumber &&
            supportsPhoneNumber.PhoneNumberConfirmed &&
            base.CanGenerateTwoFactorToken(signIn);

        public override string GetModifier(string purpose, ISignIn signIn) =>
            $"PhoneNumber:{purpose}:{(signIn as ISignInSupportsPhoneNumber).PhoneNumber}";
    }
}
