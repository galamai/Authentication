using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using System.IO;

namespace Authentication
{
    public class DataProtectorTokenProvider : ITokenProvider
    {
        private static readonly TimeSpan ConfirmationTokenLifespan = TimeSpan.FromDays(1);

        private readonly IDataProtector _protector;

        public DataProtectorTokenProvider(IDataProtectionProvider dataProtectionProvider)
        {
            _protector = dataProtectionProvider.CreateProtector(nameof(DataProtectorTokenProvider));
        }

        public virtual string Generate(string purpose, ISignIn signIn)
        {
            var memoryStream = new MemoryStream();
            using (var writer = memoryStream.CreateWriter())
            {
                writer.Write(DateTimeOffset.UtcNow);
                writer.Write(signIn.Id);
                writer.Write(purpose);
                if (signIn is ISignInSupportsSecurityStamp supportsSecurityStamp && supportsSecurityStamp.SecurityStamp != null)
                {
                    writer.Write(supportsSecurityStamp.SecurityStamp);
                }
            }

            var protectedBytes = _protector.Protect(memoryStream.ToArray());

            return Convert.ToBase64String(protectedBytes);
        }

        public virtual bool Validate(string purpose, string token, ISignIn signIn)
        {
            try
            {
                var unprotectedData = _protector.Unprotect(Convert.FromBase64String(token));
                var memoryStream = new MemoryStream(unprotectedData);
                using (var reader = memoryStream.CreateReader())
                {
                    var creationTime = reader.ReadDateTimeOffset();
                    if (DateTimeOffset.UtcNow > creationTime + ConfirmationTokenLifespan)
                    {
                        return false;
                    }

                    var storedUserId = reader.ReadString();
                    if (storedUserId != signIn.Id)
                    {
                        return false;
                    }

                    var storedPurpose = reader.ReadString();
                    if (storedPurpose != purpose)
                    {
                        return false;
                    }

                    if (signIn is ISignInSupportsSecurityStamp supportsSecurityStamp && supportsSecurityStamp.SecurityStamp != null)
                    {
                        var storedSecurityToken = reader.ReadString();
                        if (storedSecurityToken != supportsSecurityStamp.SecurityStamp)
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
            catch
            {
                // nothing
            }

            return false;
        }

        public virtual bool CanGenerateTwoFactorToken(ISignIn signIn)
        {
            return false;
        }
    }
}
