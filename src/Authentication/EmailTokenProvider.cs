using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class EmailTokenProvider : TotpSecurityStampBasedTokenProvider
    {
        public override bool CanGenerateTwoFactorToken(ISignIn signIn) =>
            signIn is ISignInSupportsEmail supportsEmail &&
            supportsEmail.EmailConfirmed &&
            base.CanGenerateTwoFactorToken(signIn);

        public override string GetModifier(string purpose, ISignIn signIn) =>
            $"Email:{purpose}:{(signIn as ISignInSupportsEmail).Email}";
    }
}
