using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ITokenProvider
    {
        string Generate(string purpose, ISignIn signIn);
        bool Validate(string purpose, string token, ISignIn signIn);
        bool CanGenerateTwoFactorToken(ISignIn signIn);
    }
}
