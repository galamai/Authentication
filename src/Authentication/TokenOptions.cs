using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class TokenOptions
    {
        public string ConfirmAccountTokenProvider { get; set; } = Provider.Phone;
        public string EmailConfirmationTokenProvider { get; set; } = Provider.DataProtector;
        public string PasswordResetTokenProvider { get; set; } = Provider.DataProtector;
        public string ChangeEmailTokenProvider { get; set; } = Provider.DataProtector;
        public string AuthenticatorTokenProvider { get; set; } = Provider.Authenticator;

        public Dictionary<string, Type> ProviderMap { get; } = new Dictionary<string, Type>();
    }
}
