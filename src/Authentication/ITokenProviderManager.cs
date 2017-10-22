using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ITokenProviderManager
    {
        IEnumerable<string> GetTwoFactorProviders(ISignIn signIn);
        ITokenProvider FindTokenProvider(string provider);
    }
}
