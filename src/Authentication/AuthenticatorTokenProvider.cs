using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace Authentication
{
    public class AuthenticatorTokenProvider : ITokenProvider
    {
        public string Generate(string purpose, ISignIn signIn)
        {
            return string.Empty;
        }

        public bool Validate(string purpose, string token, ISignIn signIn)
        {
            if (signIn is ISignInSupportsAuthenticator supportsAuthenticator)
            {
                var key = supportsAuthenticator.AuthenticatorToken;
                if (int.TryParse(token, out int code))
                {
                    var hash = new HMACSHA1(Base32.FromBase32(key));
                    var unixTimestamp = Convert.ToInt64(Math.Round((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds));
                    var timestep = Convert.ToInt64(unixTimestamp / 30);
                    for (int i = -2; i <= 2; i++)
                    {
                        var expectedCode = Rfc6238AuthenticationService.ComputeTotp(hash, (ulong)(timestep + i), modifier: null);
                        if (expectedCode == code)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public bool CanGenerateTwoFactorToken(ISignIn signIn)
        {
            return signIn is ISignInSupportsAuthenticator supportsAuthenticator &&
                !string.IsNullOrWhiteSpace(supportsAuthenticator.AuthenticatorToken);
        }
    }
}
