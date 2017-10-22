using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;

namespace Authentication
{
    public abstract class TotpSecurityStampBasedTokenProvider : ITokenProvider
    {
        public virtual string Generate(string purpose, ISignIn signIn)
        {
            if (signIn is ISignInSupportsSecurityStamp supportsSecurityStamp)
            {
                var token = GetBytes(supportsSecurityStamp.SecurityStamp);
                var modifier = GetModifier(purpose, signIn);
                return Rfc6238AuthenticationService.GenerateCode(token, modifier).ToString("D6", CultureInfo.InvariantCulture);
            }
            return String.Empty;
        }

        public virtual bool Validate(string purpose, string token, ISignIn signIn)
        {
            if (signIn is ISignInSupportsSecurityStamp supportsSecurityStamp && int.TryParse(token, out int code))
            {
                var securityToken = GetBytes(supportsSecurityStamp.SecurityStamp);
                var modifier = GetModifier(purpose, signIn);
                return securityToken != null && Rfc6238AuthenticationService.ValidateCode(securityToken, code, modifier);
            }
            return false;
        }

        public virtual bool CanGenerateTwoFactorToken(ISignIn signIn) =>
            signIn is ISignInSupportsSecurityStamp supportsSecurityStamp && supportsSecurityStamp.SecurityStamp != null;

        public virtual string GetModifier(string purpose, ISignIn signIn) => $"Totp:{purpose}:{signIn.Id}";

        private byte[] GetBytes(string payload) => Encoding.Unicode.GetBytes(payload);
    }
}
