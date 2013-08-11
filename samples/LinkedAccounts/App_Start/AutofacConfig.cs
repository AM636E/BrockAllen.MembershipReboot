﻿using Autofac;
using Autofac.Integration.Mvc;
using BrockAllen.MembershipReboot;
using System.Web.Mvc;

namespace LinkedAccounts
{
    public class AutofacConfig
    {
        public static MembershipRebootConfiguration CreateMembershipRebootConfiguration()
        {
            var settings = SecuritySettings.Instance;
            settings.MultiTenant = false;

            var config = new MembershipRebootConfiguration(settings, new DelegateFactory(() => new DefaultUserAccountRepository(settings.ConnectionStringName)));
            return config;
        }

        internal static void Register()
        {
            var config = CreateMembershipRebootConfiguration();

            var builder = new ContainerBuilder();

            builder.RegisterType<UserAccountService>();
            builder.RegisterType<SamAuthenticationService>().As<AuthenticationService>();

            builder
                .Register<DefaultUserAccountRepository>(x=>new DefaultUserAccountRepository(config.SecuritySettings.ConnectionStringName))
                .As<IUserAccountRepository>()
                .InstancePerHttpRequest();

            builder.RegisterControllers(typeof(AutofacConfig).Assembly);
            var container = builder.Build();
            DependencyResolver.SetResolver(new AutofacDependencyResolver(container));
        }
    }
}