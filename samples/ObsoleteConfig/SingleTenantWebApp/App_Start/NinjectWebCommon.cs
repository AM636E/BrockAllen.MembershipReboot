[assembly: WebActivator.PreApplicationStartMethod(typeof(BrockAllen.MembershipReboot.Mvc.App_Start.NinjectWebCommon), "Start")]
[assembly: WebActivator.ApplicationShutdownMethodAttribute(typeof(BrockAllen.MembershipReboot.Mvc.App_Start.NinjectWebCommon), "Stop")]

namespace BrockAllen.MembershipReboot.Mvc.App_Start
{
    using System;
    using System.Web;
    using BrockAllen.MembershipReboot;
    using Microsoft.Web.Infrastructure.DynamicModuleHelper;
    using Ninject;
    using Ninject.Web.Common;

    public static class NinjectWebCommon 
    {
        private static readonly Bootstrapper bootstrapper = new Bootstrapper();

        /// <summary>
        /// Starts the application
        /// </summary>
        public static void Start() 
        {
            DynamicModuleUtility.RegisterModule(typeof(OnePerRequestHttpModule));
            DynamicModuleUtility.RegisterModule(typeof(NinjectHttpModule));
            bootstrapper.Initialize(CreateKernel);
        }
        
        /// <summary>
        /// Stops the application.
        /// </summary>
        public static void Stop()
        {
            bootstrapper.ShutDown();
        }
        
        /// <summary>
        /// Creates the kernel that will manage your application.
        /// </summary>
        /// <returns>The created kernel.</returns>
        private static IKernel CreateKernel()
        {
            var kernel = new StandardKernel();
            kernel.Bind<Func<IKernel>>().ToMethod(ctx => () => new Bootstrapper().Kernel);
            kernel.Bind<IHttpModule>().To<HttpApplicationInitializationHttpModule>();
            
            RegisterServices(kernel);
            return kernel;
        }

        /// <summary>
        /// Load your modules or register your services here!
        /// </summary>
        /// <param name="kernel">The kernel.</param>
        private static void RegisterServices(IKernel kernel)
        {
            kernel
                .Bind<IUserAccountRepository>()
                .ToMethod<EFUserAccountRepository>(ctx=>new EFUserAccountRepository(SecuritySettings.Instance.ConnectionStringName))
                .InRequestScope();
            
            //kernel.Bind<IMessageDelivery>().To<NopMessageDelivery>();
            kernel.Bind<IMessageDelivery>().To<SmtpMessageDelivery>();
            
            //kernel.Bind<IPasswordPolicy>().To<NopPasswordPolicy>();
            kernel.Bind<IPasswordPolicy>().ToMethod(x => new BasicPasswordPolicy { MinLength = 4 });

            kernel.Bind<INotificationService>().To<NotificationService>();
            
            kernel
                .Bind<ApplicationInformation>()
                .ToMethod(x=>
                    {
                        // build URL
                        var baseUrl = HttpContext.Current.GetApplicationUrl();
                        // area name
                        baseUrl += "UserAccount/";
                        
                        return new ApplicationInformation { 
                            ApplicationName="Test",
                            LoginUrl = baseUrl + "Login",
                            VerifyAccountUrl = baseUrl + "Register/Confirm/",
                            CancelNewAccountUrl = baseUrl + "Register/Cancel/",
                            ConfirmPasswordResetUrl = baseUrl + "PasswordReset/Confirm/",
                            ConfirmChangeEmailUrl = baseUrl + "ChangeEmail/Confirm/"
                        };
                    });
        }        
    }
}
