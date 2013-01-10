﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;
using System.Web.Helpers;

namespace BrockAllen.MembershipReboot
{
    public class UserAccountService : IDisposable
    {
        IUserAccountRepository userRepository;
        NotificationService notificationService;
        IPasswordPolicy passwordPolicy;

        public UserAccountService(
            IUserAccountRepository userAccountRepository,
            NotificationService notificationService,
            IPasswordPolicy passwordPolicy)
        {
            this.userRepository = userAccountRepository;
            this.notificationService = notificationService;
            this.passwordPolicy = passwordPolicy;
        }

        public void Dispose()
        {
            if (this.userRepository != null)
            {
                this.userRepository.Dispose();
                this.userRepository = null;
            }
        }

        public void SaveChanges()
        {
            this.userRepository.SaveChanges();
        }

        public virtual IQueryable<UserAccount> GetAll()
        {
            return GetAll(null);
        }
        
        public virtual IQueryable<UserAccount> GetAll(string tenant)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return Enumerable.Empty<UserAccount>().AsQueryable();

            return this.userRepository.GetAll().Where(x => x.Tenant == tenant && x.IsAccountClosed == false);
        }

        public virtual UserAccount GetByUsername(string username)
        {
            return GetByUsername(null, username);
        }

        public virtual UserAccount GetByUsername(string tenant, string username)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return null;
            if (String.IsNullOrWhiteSpace(username)) return null;

            return userRepository.GetAll().Where(x => x.Tenant == tenant && x.Username == username).SingleOrDefault();
        }

        public virtual UserAccount GetByEmail(string email)
        {
            return GetByEmail(null, email);
        }

        public virtual UserAccount GetByEmail(string tenant, string email)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return null;
            if (String.IsNullOrWhiteSpace(email)) return null;

            return userRepository.GetAll().Where(x => x.Tenant == tenant && x.Email == email).SingleOrDefault();
        }

        public virtual UserAccount GetByVerificationKey(string key)
        {
            if (String.IsNullOrWhiteSpace(key)) return null;

            return userRepository.GetAll().Where(x => x.VerificationKey == key).SingleOrDefault();
        }

        public virtual bool UsernameExists(string username)
        {
            return UsernameExists(null, username);
        }

        public virtual bool UsernameExists(string tenant, string username)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(username)) return false;

            if (SecuritySettings.Instance.UsernamesUniqueAcrossTenants)
            {
                return this.userRepository.GetAll().Where(x => x.Username == username).Any();
            }
            else
            {
                return this.userRepository.GetAll().Where(x => x.Tenant == tenant && x.Username == username).Any();
            }
        }

        public virtual bool EmailExists(string email)
        {
            return EmailExists(null, email);
        }

        public virtual bool EmailExists(string tenant, string email)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(email)) return false;

            return this.userRepository.GetAll().Where(x => x.Tenant == tenant && x.Email == email).Any();
        }

        public virtual UserAccount CreateAccount(string username, string password, string email)
        {
            return CreateAccount(null, username, password, email);
        }

        public virtual UserAccount CreateAccount(string tenant, string username, string password, string email)
        {
            if (SecuritySettings.Instance.EmailIsUsername)
            {
                username = email;
            }

            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) throw new ArgumentException("tenant");
            if (String.IsNullOrWhiteSpace(username)) throw new ArgumentException("username");
            if (String.IsNullOrWhiteSpace(password)) throw new ArgumentException("password");
            if (String.IsNullOrWhiteSpace(email)) throw new ArgumentException("email");
            
            ValidatePassword(password);

            EmailAddressAttribute validator = new EmailAddressAttribute();
            if (!validator.IsValid(email))
            {
                throw new ValidationException("Email is invalid.");
            }

            if (UsernameExists(tenant, username))
            {
                var msg = SecuritySettings.Instance.EmailIsUsername ? "Email" : "Username";
                throw new ValidationException(msg + " already in use.");
            }

            if (EmailExists(tenant, username))
            {
                throw new ValidationException("Email already in use.");
            } 
            
            using (var tx = new TransactionScope())
            {
                var account = UserAccount.Create(tenant, username, password, email);
                this.userRepository.Add(account);
                this.userRepository.SaveChanges();
                
                if (this.notificationService != null)
                {
                    if (SecuritySettings.Instance.RequireAccountVerification)
                    {
                        this.notificationService.SendAccountCreate(account);
                    }
                    else
                    {
                        this.notificationService.SendAccountVerified(account);
                    }
                }
                
                tx.Complete();

                return account;
            }
        }

        public virtual bool VerifyAccount(string key)
        {
            var account = this.GetByVerificationKey(key);
            if (account == null) return false;

            var result = account.VerifyAccount(key);
            using (var tx = new TransactionScope())
            {
                this.userRepository.SaveChanges();
                
                if (result && this.notificationService != null)
                {
                    this.notificationService.SendAccountVerified(account);
                }

                tx.Complete();
            }
            return result;
        }

        public virtual bool CancelNewAccount(string key)
        {
            var account = this.GetByVerificationKey(key);
            if (account == null) return false;

            if (account.IsAccountVerified) return false;
            if (account.VerificationKey != key) return false;

            DeleteAccount(account);

            return true;
        }

        public virtual bool DeleteAccount(string username)
        {
            return DeleteAccount(null, username);
        }

        public virtual bool DeleteAccount(string tenant, string username)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(username)) return false;

            var account = this.GetByUsername(tenant, username);
            if (account == null) return false;

            DeleteAccount(account);

            return true;
        }

        private void DeleteAccount(UserAccount account)
        {
            if (SecuritySettings.Instance.AllowAccountDeletion || !account.IsAccountVerified)
            {
                this.userRepository.Remove(account);
            }
            else
            {
                account.IsLoginAllowed = false;
                account.IsAccountClosed = true;
            }

            using (var tx = new TransactionScope())
            {
                this.userRepository.SaveChanges();

                if (this.notificationService != null)
                {
                    this.notificationService.SendAccountDelete(account);
                }

                tx.Complete();
            }
        }

        public virtual bool Authenticate(string username, string password)
        {
            return Authenticate(null, username, password);
        }

        public virtual bool Authenticate(string tenant, string username, string password)
        {
            return Authenticate(
                tenant, username, password,
                SecuritySettings.Instance.AccountLockoutFailedLoginAttempts, 
                SecuritySettings.Instance.AccountLockoutDuration);
        }

        public virtual bool Authenticate(
            string username, string password,
            int failedLoginCount, TimeSpan lockoutDuration)
        {
            return Authenticate(null, username, password, failedLoginCount, lockoutDuration);
        }

        public virtual bool Authenticate(
            string tenant, string username, string password, 
            int failedLoginCount, TimeSpan lockoutDuration)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(username)) return false;
            if (String.IsNullOrWhiteSpace(password)) return false;

            var account = this.GetByUsername(tenant, username);
            if (account == null) return false;

            return Authenticate(account, password, failedLoginCount, lockoutDuration);
        }

        private bool Authenticate(UserAccount account, string password, int failedLoginCount, TimeSpan lockoutDuration)
        {
            var result = account.Authenticate(password, failedLoginCount, lockoutDuration);
            this.userRepository.SaveChanges();
            return result;
        }

        public virtual bool ChangePassword(
            string username, string oldPassword, string newPassword)
        {
            return ChangePassword(null, username, oldPassword, newPassword);
        }

        public virtual bool ChangePassword(
            string tenant, string username, 
            string oldPassword, string newPassword)
        {
            return ChangePassword(
                tenant, username, 
                oldPassword, newPassword,
                SecuritySettings.Instance.AccountLockoutFailedLoginAttempts,
                SecuritySettings.Instance.AccountLockoutDuration);
        }

        public virtual bool ChangePassword(
            string username,
            string oldPassword, string newPassword,
            int failedLoginCount, TimeSpan lockoutDuration)
        {
            return ChangePassword(null, username, oldPassword, newPassword, failedLoginCount, lockoutDuration);
        }

        public virtual bool ChangePassword(
            string tenant, string username, 
            string oldPassword, string newPassword,
            int failedLoginCount, TimeSpan lockoutDuration)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(username)) return false;
            if (String.IsNullOrWhiteSpace(oldPassword)) return false;
            if (String.IsNullOrWhiteSpace(newPassword)) return false;

            ValidatePassword(newPassword);

            var account = this.GetByUsername(tenant, username);
            if (account == null) return false;

            var result = account.ChangePassword(oldPassword, newPassword, failedLoginCount, lockoutDuration);
            using (var tx = new TransactionScope())
            {
                this.userRepository.SaveChanges();

                if (result && this.notificationService != null)
                {
                    this.notificationService.SendPasswordChangeNotice(account);
                }
                
                tx.Complete();
            }
            return result;
        }

        public virtual bool ResetPassword(string email)
        {
            return ResetPassword(null, email);
        }

        public virtual bool ResetPassword(string tenant, string email)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(email)) return false;

            var account = this.GetByEmail(tenant, email);
            if (account == null) return false;

            if (!account.IsAccountVerified)
            {
                // if they're not verified, resend the new account email
                if (SecuritySettings.Instance.RequireAccountVerification && 
                    this.notificationService != null)
                {
                    this.notificationService.SendAccountCreate(account);
                    return true;
                }

                // if we don't have a notification system then not much we can do
                return false;
            }

            var result = account.ResetPassword();
            if (result)
            {
                using (var tx = new TransactionScope())
                {
                    this.userRepository.SaveChanges();
 
                    if (this.notificationService != null)
                    {
                        this.notificationService.SendResetPassword(account);
                    }
 
                    tx.Complete();
                }
            }
            return result;
        }
        
        public virtual bool ChangePasswordFromResetKey(string key, string newPassword)
        {
            if (String.IsNullOrWhiteSpace(key))
            {
                return false;
            }

            var account = this.GetByVerificationKey(key);
            if (account == null) return false;

            ValidatePassword(newPassword);

            var result = account.ChangePasswordFromResetKey(key, newPassword);
            if (result)
            {
                using (var tx = new TransactionScope())
                {
                    this.userRepository.SaveChanges();

                    if (this.notificationService != null)
                    {
                        this.notificationService.SendPasswordChangeNotice(account);
                    }

                    tx.Complete();
                }
            }
            return result;
        }

        public virtual void SendUsernameReminder(string email)
        {
            SendUsernameReminder(null, email);
        }

        public virtual void SendUsernameReminder(string tenant, string email)
        {
            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return;
            if (String.IsNullOrWhiteSpace(email)) return;

            var user = this.GetByEmail(tenant, email);
            if (user != null)
            {
                this.notificationService.SendAccountNameReminder(user);
            }
        }

        public virtual bool ChangeEmailRequest(string username, string newEmail)
        {
            return ChangeEmailRequest(null, username, newEmail);
        }

        public virtual bool ChangeEmailRequest(string tenant, string username, string newEmail)
        {
            if (SecuritySettings.Instance.EmailIsUsername)
            {
                // if username is email, then this is same as 
                // changing the primary key, so we don't allow it
                return false;
            }

            if (!SecuritySettings.Instance.MultiTenant)
            {
                tenant = SecuritySettings.Instance.DefaultTenant;
            }

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(username)) return false;
            if (String.IsNullOrWhiteSpace(newEmail)) return false;

            EmailAddressAttribute validator = new EmailAddressAttribute();
            if (!validator.IsValid(newEmail))
            {
                throw new ValidationException("Email is invalid.");
            }

            var account = this.GetByUsername(tenant, username);
            if (account == null) return false;

            var result = account.ChangeEmailRequest(newEmail);
            if (result)
            {
                using (var tx = new TransactionScope())
                {
                    this.userRepository.SaveChanges();
                    
                    if (this.notificationService != null)
                    {
                        this.notificationService.SendChangeEmailRequestNotice(account, newEmail);
                    }

                    tx.Complete();
                }
            }

            return result;
        }

        public virtual bool ChangeEmailFromKey(string password, string key, string newEmail)
        {
            return ChangeEmailFromKey(
                password, key, newEmail, 
                SecuritySettings.Instance.AccountLockoutFailedLoginAttempts, 
                SecuritySettings.Instance.AccountLockoutDuration);
        }
        
        public virtual bool ChangeEmailFromKey(
            string password, string key, string newEmail, 
            int failedLoginCount, TimeSpan lockoutDuration)
        {
            if (String.IsNullOrWhiteSpace(password)) return false;
            if (String.IsNullOrWhiteSpace(key)) return false;
            if (String.IsNullOrWhiteSpace(newEmail)) return false;

            var account = this.GetByVerificationKey(key);
            if (account == null) return false;

            if (!Authenticate(account, password, failedLoginCount, lockoutDuration))
            {
                return false;
            }

            var oldEmail = account.Email;
            var result = account.ChangeEmailFromKey(key, newEmail);
            if (result)
            {
                using (var tx = new TransactionScope())
                {
                    this.userRepository.SaveChanges();

                    if (this.notificationService != null)
                    {
                        this.notificationService.SendEmailChangedNotice(account, oldEmail);
                    }

                    tx.Complete();
                }
            }
            return result;
        }

        private void ValidatePassword(string password)
        {
            if (passwordPolicy != null &&
                !passwordPolicy.ValidatePassword(password))
            {
                throw new ValidationException("Invalid password: " + passwordPolicy.PolicyMessage);
            }
        }
    }
}
