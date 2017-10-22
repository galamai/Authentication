using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class TokenProviderManager : ITokenProviderManager
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly TokenOptions _options;

        public TokenProviderManager(IServiceProvider serviceProvider, IOptions<TokenOptions> optionsAccessor)
        {
            _serviceProvider = serviceProvider;
            _options = optionsAccessor.Value;
        }

        public ITokenProvider FindTokenProvider(string provider)
        {
            if (_options.ProviderMap.ContainsKey(provider))
            {
                return (ITokenProvider)_serviceProvider.GetService(_options.ProviderMap[provider]);
            }
            return null;
        }

        public IEnumerable<string> GetTwoFactorProviders(ISignIn signIn)
        {
            var providers = new List<string>();
            foreach (var kv in _options.ProviderMap)
            {
                var provider = (ITokenProvider)_serviceProvider.GetService(kv.Value);
                if (provider.CanGenerateTwoFactorToken(signIn))
                {
                    providers.Add(kv.Key);
                }
            }
            return providers;
        }
    }
}
