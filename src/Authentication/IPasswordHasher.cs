using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface IPasswordHasher
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string passwordHash);
    }
}
