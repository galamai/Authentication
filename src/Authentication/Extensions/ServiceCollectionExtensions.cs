using Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddDefaultTokenProviders(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.Configure<TokenOptions>(options =>
            {
                options.ProviderMap.Add(Provider.DataProtector, typeof(DataProtectorTokenProvider));
                options.ProviderMap.Add(Provider.Email, typeof(EmailTokenProvider));
                options.ProviderMap.Add(Provider.Phone, typeof(PhoneNumberTokenProvider));
                options.ProviderMap.Add(Provider.Authenticator, typeof(AuthenticatorTokenProvider));
            });

            services.AddScoped<DataProtectorTokenProvider, DataProtectorTokenProvider>();
            services.AddScoped<AuthenticatorTokenProvider, AuthenticatorTokenProvider>();
            services.AddScoped<PhoneNumberTokenProvider, PhoneNumberTokenProvider>();
            services.AddScoped<EmailTokenProvider, EmailTokenProvider>();

            return services;
        }

        public static IServiceCollection AddSignInManager(this IServiceCollection services, Action<SignInManagerOptions> setupAction = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (setupAction != null)
            {
                services.Configure(setupAction);
            }

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SignInConstants.ApplicationScheme;
                options.DefaultChallengeScheme = SignInConstants.ApplicationScheme;
                options.DefaultSignInScheme = SignInConstants.ExternalScheme;
            })
            
            .AddCookie(SignInConstants.ApplicationScheme, o =>
            {
                o.LoginPath = new PathString("/Account/Login");
                o.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync
                };
            })
            
            .AddCookie(SignInConstants.ExternalScheme, o =>
            {
                o.Cookie.Name = SignInConstants.ExternalScheme;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            })
            
            .AddCookie(SignInConstants.TwoFactorRememberMeScheme, o =>
                o.Cookie.Name = SignInConstants.TwoFactorRememberMeScheme)
            
            .AddCookie(SignInConstants.TwoFactorUserIdScheme, o =>
            {
                o.Cookie.Name = SignInConstants.TwoFactorUserIdScheme;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });

            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddScoped<IPasswordHasher, PasswordHasher>();
            services.AddScoped<IClaimsPrincipalFactory, ClaimsPrincipalFactory>();
            services.AddScoped<ISecurityStampValidator, SecurityStampValidator>();
            services.AddScoped<ITokenProviderManager, TokenProviderManager>();
            services.AddScoped<ISignInManager, SignInManager>();

            return services;
        }
    }
}
