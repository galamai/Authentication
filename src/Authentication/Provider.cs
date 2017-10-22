using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public static class Provider
    {
        public const string DataProtector = nameof(DataProtector);
        public const string Email = nameof(Email);
        public const string Phone = nameof(Phone);
        public const string Authenticator = nameof(Authenticator);
        public const string Code = nameof(Code);
    }
}
