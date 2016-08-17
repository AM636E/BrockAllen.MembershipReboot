/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Linq;

namespace BrockAllen.MembershipReboot
{
    public class MembershipRebootConfiguration<TAccount>
        where TAccount : UserAccount
    {
        public bool MultiTenant { get; set; }
        public string DefaultTenant { get; set; }
        public bool EmailIsUnique { get; set; }
        public bool EmailIsUsername { get; set; }
        public bool UsernamesUniqueAcrossTenants { get; set; }
        public bool RequireAccountVerification { get; set; }
        public bool AllowLoginAfterAccountCreation { get; set; }
        public int AccountLockoutFailedLoginAttempts { get; set; }
        public TimeSpan AccountLockoutDuration { get; set; }
        public bool AllowAccountDeletion { get; set; }
        public int PasswordHashingIterationCount { get; set; }
        public int PasswordResetFrequency { get; set; }
        public TimeSpan VerificationKeyLifetime { get; set; }

        private readonly AggregateValidator<TAccount> _usernameValidators = new AggregateValidator<TAccount>();
        public IValidator<TAccount> UsernameValidator => _usernameValidators;

        private readonly AggregateValidator<TAccount> _passwordValidators = new AggregateValidator<TAccount>();

        public IValidator<TAccount> PasswordValidator => _passwordValidators;

        private readonly AggregateValidator<TAccount> _emailValidators = new AggregateValidator<TAccount>();
        public IValidator<TAccount> EmailValidator => _emailValidators;

        public MembershipRebootConfiguration()
            : this(SecuritySettings.Instance)
        {
        }

        public MembershipRebootConfiguration(SecuritySettings securitySettings)
        {
            if (securitySettings == null) throw new ArgumentNullException(nameof(securitySettings));

            this.MultiTenant = securitySettings.MultiTenant;
            this.DefaultTenant = securitySettings.DefaultTenant;
            this.EmailIsUnique = securitySettings.EmailIsUnique;
            this.EmailIsUsername = securitySettings.EmailIsUsername;
            this.UsernamesUniqueAcrossTenants = securitySettings.UsernamesUniqueAcrossTenants;
            this.RequireAccountVerification = securitySettings.RequireAccountVerification;
            this.AllowLoginAfterAccountCreation = securitySettings.AllowLoginAfterAccountCreation;
            this.AccountLockoutFailedLoginAttempts = securitySettings.AccountLockoutFailedLoginAttempts;
            this.AccountLockoutDuration = securitySettings.AccountLockoutDuration;
            this.AllowAccountDeletion = securitySettings.AllowAccountDeletion;
            this.PasswordHashingIterationCount = securitySettings.PasswordHashingIterationCount;
            this.PasswordResetFrequency = securitySettings.PasswordResetFrequency;
            this.VerificationKeyLifetime = securitySettings.VerificationKeyLifetime;

            this.Crypto = new DefaultCrypto();

            if (!this.EmailIsUsername)
            {
                _usernameValidators.Add("UsernameDoesNotContainAtSign", UserAccountValidation<TAccount>.UsernameDoesNotContainAtSign);
                _usernameValidators.Add("UsernameCanOnlyStartOrEndWithLetterOrDigit", UserAccountValidation<TAccount>.UsernameCanOnlyStartOrEndWithLetterOrDigit);
                _usernameValidators.Add("UsernameOnlyContainsValidCharacters", UserAccountValidation<TAccount>.UsernameOnlyContainsValidCharacters);
                _usernameValidators.Add("UsernameOnlySingleInstanceOfSpecialCharacters", UserAccountValidation<TAccount>.UsernameOnlySingleInstanceOfSpecialCharacters);
            }
            _usernameValidators.Add("UsernameMustNotAlreadyExist", UserAccountValidation<TAccount>.UsernameMustNotAlreadyExist);

            _emailValidators.Add("EmailIsRequiredIfRequireAccountVerificationEnabled", UserAccountValidation<TAccount>.EmailIsRequiredIfRequireAccountVerificationEnabled);
            _emailValidators.Add("EmailIsValidFormat", UserAccountValidation<TAccount>.EmailIsValidFormat);
            if (this.EmailIsUnique)
            {
                _emailValidators.Add("EmailMustNotAlreadyExist", UserAccountValidation<TAccount>.EmailMustNotAlreadyExist);
            }

            _passwordValidators.Add("PasswordMustBeDifferentThanCurrent", UserAccountValidation<TAccount>.PasswordMustBeDifferentThanCurrent);
        }

        internal void Validate()
        {
            if (this.EmailIsUnique) return;
            if (this.EmailIsUsername)
            {
                throw new InvalidOperationException("EmailMustBeUnique is false and EmailIsUsername is true");
            }
        }

        public void RegisterUsernameValidator(params KeyValuePair<string, IValidator<TAccount>>[] items)
        {
            foreach (var item in items)
            {
                _usernameValidators[item.Key] = item.Value;
            }
        }

        public void RegisterUsernameValidator(params IValidator<TAccount>[] items)
        {
            RegisterUsernameValidator(items.Select(it => new KeyValuePair<string, IValidator<TAccount>>(it.GetType().Name, it)).ToArray());
        }

        public void RegisterPasswordValidator(params KeyValuePair<string, IValidator<TAccount>>[] items)
        {
            foreach (var item in items)
            {
                _passwordValidators[item.Key] = item.Value;
            }
        }

        public void RegisterPasswordValidator(params IValidator<TAccount>[] items)
        {
            RegisterPasswordValidator(items.Select(it => new KeyValuePair<string, IValidator<TAccount>>(it.GetType().Name, it)).ToArray());
        }

        public void UnregisterUsernameValidator(string name)
        {
            if (_usernameValidators.ContainsKey(name))
                _usernameValidators.Remove(name);
        }

        public void RegisterEmailValidator(params KeyValuePair<string, IValidator<TAccount>>[] items)
        {
            foreach (var item in items)
            {
                _emailValidators[item.Key] = item.Value;
            }
        }

        public void RegisterEmailValidator(params IValidator<TAccount>[] items)
        {
            RegisterEmailValidator(items.Select(it => new KeyValuePair<string, IValidator<TAccount>>(it.GetType().Name, it)).ToArray());
        }

        EventBus eventBus = new EventBus();
        public IEventBus EventBus { get { return eventBus; } }
        public void AddEventHandler(params IEventHandler[] handlers)
        {
            foreach (var h in handlers) VerifyHandler(h);
            eventBus.AddRange(handlers);
        }

        EventBus validationBus = new EventBus();
        public IEventBus ValidationBus { get { return validationBus; } }
        public void AddValidationHandler(params IEventHandler[] handlers)
        {
            foreach (var h in handlers) VerifyHandler(h);
            validationBus.AddRange(handlers);
        }

        CommandBus commandBus = new CommandBus();
        public ICommandBus CommandBus => commandBus;

        public void AddCommandHandler(ICommandHandler handler)
        {
            VerifyHandler(handler);
            commandBus.Add(handler);
        }

        private void VerifyHandler(IEventHandler e)
        {
            var type = e.GetType();
            var interfaces = type.GetInterfaces();
            foreach (var itf in interfaces)
            {
                if (itf.IsGenericType && itf.GetGenericTypeDefinition() == typeof(IEventHandler<>))
                {
                    var eventHandlerType = itf.GetGenericArguments()[0];
                    if (eventHandlerType.IsGenericType)
                    {
                        var targetUserAccountType = eventHandlerType.GetGenericArguments()[0];
                        var isSameType = targetUserAccountType == typeof(TAccount);
                        if (!isSameType)
                        {
                            throw new ArgumentException(String.Format("Event handler: {0} must handle events for User Account type: {1}",
                                e.GetType().FullName,
                                typeof(TAccount).FullName));
                        }
                    }
                }
            }
        }
        private void VerifyHandler(ICommandHandler e)
        {
            var type = e.GetType();
            var interfaces = type.GetInterfaces();
            foreach (var itf in interfaces)
            {
                if (itf.IsGenericType && itf.GetGenericTypeDefinition() == typeof(ICommandHandler<>))
                {
                    var eventHandlerType = itf.GetGenericArguments()[0];
                    if (eventHandlerType.IsGenericType)
                    {
                        var targetUserAccountType = eventHandlerType.GetGenericArguments()[0];
                        var isSameType = targetUserAccountType == typeof(TAccount);
                        if (!isSameType)
                        {
                            throw new ArgumentException(
                                $"Command handler: {e.GetType().FullName} must handle commands for User Account type: {typeof(TAccount).FullName}");
                        }
                    }
                }
            }
        }

        public ICrypto Crypto { get; set; }
    }

    public class MembershipRebootConfiguration : MembershipRebootConfiguration<UserAccount>
    {
        public MembershipRebootConfiguration()
            : this(SecuritySettings.Instance)
        {
        }

        public MembershipRebootConfiguration(SecuritySettings securitySettings)
            : base(securitySettings)
        {
        }
    }
}
