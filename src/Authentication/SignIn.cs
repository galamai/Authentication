using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class SignIn : ISignIn
    {
        public string Id { get; }
        public string Name { get; }

        public SignIn(string id, string name)
        {
            Id = id;
            Name = name;
        }
    }
}
