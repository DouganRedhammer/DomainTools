using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.Diagnostics;
using System.Net.Mail;
using System.Net;
using System.Net.NetworkInformation;

namespace DomainToolBox
{

    public class DomainTools
    {
        string username;
        string password;
        string connection;
        string domainController;
        string domain;
        string dotSuffix;
        string OU;
        PrincipalContext ctx;

        public DomainTools(string domain, string dotSuffix, string OU)
        {
            this.domain = domain;
            this.dotSuffix = dotSuffix;
            this.OU = OU;
            this.ctx = new PrincipalContext(ContextType.Domain, domain +"."+ dotSuffix, OU + ",dc=" + domain + ",dc="+dotSuffix);             
        }

        public bool testADConnection()
        {
            try
            {
                //just a quick and dirty way to test ctx
                UserPrincipal qbeUser = new UserPrincipal(this.ctx);
                PrincipalSearcher userSrch = new PrincipalSearcher(qbeUser);
            }
            catch (System.DirectoryServices.AccountManagement.PrincipalOperationException e)
            {
                return false;
            }

            return true;
        }

        public List<string> ListDomainComputers()
        {
            List<string> domainComputers = new List<string>();

            ComputerPrincipal cpt = new ComputerPrincipal(this.ctx);

            PrincipalSearcher computersrch = new PrincipalSearcher(cpt);

            foreach (var found in computersrch.FindAll())
            {
                domainComputers.Add(found.Name);
            }

            cpt.Dispose();
            this.ctx.Dispose();

            return domainComputers;
        }

        public List<string> ListDomainUsers()
        {
            List<string> domainUsers = new List<string>();

            UserPrincipal qbeUser = new UserPrincipal(this.ctx);

            PrincipalSearcher userSrch = new PrincipalSearcher(qbeUser);

            foreach (var found in userSrch.FindAll())
            {
                domainUsers.Add(found.Name);
            }

            qbeUser.Dispose();
            this.ctx.Dispose();

            return domainUsers;
        }
        public List<string> ListDomainUserNames()
        {
            List<string> domainUsers = new List<string>();

            UserPrincipal qbeUser = new UserPrincipal(this.ctx);

            PrincipalSearcher userSrch = new PrincipalSearcher(qbeUser);

            foreach (var found in userSrch.FindAll())
            {
                domainUsers.Add(found.SamAccountName);
            }

            qbeUser.Dispose();
            this.ctx.Dispose();

            return domainUsers;
        }

        public List<string> ListDomainUsersEmailAddress()
        {
            List<string> domainUsersEmailAddress = new List<string>();

            UserPrincipal qbeUser = new UserPrincipal(this.ctx);

            PrincipalSearcher userSrch = new PrincipalSearcher(qbeUser);

            foreach (var found in userSrch.FindAll())
            {
                UserPrincipal usr = (UserPrincipal)found;
                if (usr.EmailAddress != "")
                    domainUsersEmailAddress.Add(usr.EmailAddress);
            }

            qbeUser.Dispose();
            this.ctx.Dispose();

            return domainUsersEmailAddress;
        }

        /// <summary>
        /// Get the login time of the user that is currently logged in 
        /// 
        /// </summary>
        /// <param name="workstation"></param>
        /// <pre>workstation cannot be the local computer.</pre>
        /// <returns></returns>
        public string LatestInteractiveSession(string workstation)
        {
            if (workstation == Environment.MachineName)
                return "localmachine";
            List<string> startTimes = new List<string>();
            try
            {
                ManagementScope scope = new ManagementScope("\\\\" + workstation + "\\root\\CIMV2");
                scope.Connect();
                WqlObjectQuery wqlQuery = new WqlObjectQuery("SELECT *  FROM Win32_LogonSession Where LogonType=2");
                ManagementObjectSearcher s = new ManagementObjectSearcher(scope, wqlQuery);
                foreach (ManagementObject x in s.Get())
                {
                    DateTime dt = ManagementDateTimeConverter.ToDateTime(x["StartTime"].ToString());
                    startTimes.Add(dt.ToString());
                    // Console.WriteLine(dt);
                }
            }
            catch (System.UnauthorizedAccessException e) { return "access denied"; }
            catch (System.Runtime.InteropServices.COMException e) { return "No active session"; }
            if (startTimes.Count > 0)
                return startTimes[0];
            else
                return "no active sessions";


        }

        /// <summary>
        /// Get the login time of the user that is currently logged in 
        /// 
        /// </summary>
        /// <param name="workstation"></param>
        /// <pre>workstation cannot be the local computer.</pre>
        /// <returns></returns>
        public string WhoIsLoggedOn(string workstation)
        {
            List<string> users = new List<string>();

            try
            {
                ManagementScope scope = new ManagementScope("\\\\" + workstation + "\\root\\CIMV2");
                scope.Connect();

                WqlObjectQuery wqlQuery2 = new WqlObjectQuery("SELECT *  FROM Win32_ComputerSystem");

                ManagementObjectSearcher s2 = new ManagementObjectSearcher(scope, wqlQuery2);

                foreach (ManagementObject x in s2.Get())
                {
                    users.Add(x["UserName"].ToString());
                }
            }
            catch (System.UnauthorizedAccessException e) { return "Noone is logged on."; }
            if (users.Count > 0)
                return users[0];
            else
                return "Noone is logged on.";
        }

        /// <summary>
        ///  This returns a string of the current user and the start of their session on that workstation
        /// </summary>
        /// <param name="workstation"></param>
        /// <returns></returns>
        public string CurrentWorkstationSession(string workstation)
        {
            string currentSession;
            /* 
             * This is really crappy. Need to refactor. works for now
             */
            if (canConnect(workstation))
            {
                if (FindDomainComputer(workstation))
                {
                    string status = LatestInteractiveSession(workstation);
                    if (status == "localmachine")
                        return "Cannot query sessions of the local machine.";
                    else if (status == "access denied")
                        return workstation + " Not connected or is blocked by a firewall.";
                    else if (status == "no active sessions")
                        return status;
                    else
                        currentSession = WhoIsLoggedOn(workstation) + " Latest session: " + LatestInteractiveSession(workstation);
                }
                else
                    currentSession = "There are no active sessions on " + workstation + ".";
            }
            else
                currentSession = "There are no active sessions on " + workstation + ".";
            return currentSession;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="workstation"></param>
        /// <returns></returns>
        public bool canConnect(string workstation)
        {
            try
            {
                ManagementScope scope = new ManagementScope("\\\\" + workstation + "\\root\\CIMV2");
                scope.Connect();

                if (scope.IsConnected)
                {

                    return true;
                }
            }
            catch (Exception e)
            {
                return false;
            }

            return false;
        }
        public bool Disconnect()
        {
            return true;
        }


        public bool FindDomainComputer(string workstation)
        {
            List<string> domainComputers = new List<string>();

            ComputerPrincipal cpt = ComputerPrincipal.FindByIdentity(ctx, workstation);

            if (cpt == null)
                return false;
            else
                return true;
        }

        /// <summary>
        /// Have to add some excecption handling
        /// </summary>
        /// <param name="workstation"></param>
        public void RebootWorkstation(string workstation)
        {
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = @"shutdown.exe"; // Specify exe name.
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.Arguments = "/r /f /t 0 /m \\\\" + workstation;
            start.WindowStyle = ProcessWindowStyle.Hidden;
            Process process = Process.Start(start);
        }
        
        public bool canPingWorkstation(string workstation)
        {
            string notfound = "could not find host";
            string timedOut = "Request timed out.";
            string unreachable = "host unreachable";
            try
            {
                Ping pingSender = new Ping();
                PingReply reply = pingSender.Send(workstation);
                if (reply.Status != IPStatus.Success)
                    return false;
                else
                    return true;
            }
            catch(System.Net.NetworkInformation.PingException e)
            {
                return false;
            }
            /*    ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = @"ping.exe /c "; // Specify exe name.
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.Arguments = "-n 1 "+ workstation;
            start.WindowStyle = ProcessWindowStyle.Hidden;
            Process process = Process.Start(start);
            string result = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            if (result.Contains(timedOut) || result.Contains(unreachable) || result.Contains(notfound))
                return false;
            else
                return true;
         * */
        }

        public string windowsVersion(string workstation)
        {
            List<string> version = new List<string>();
            try
            {
                ManagementScope scope = new ManagementScope("\\\\" + workstation + "\\root\\CIMV2");
                scope.Connect();

                WqlObjectQuery wqlQuery = new WqlObjectQuery("SELECT *  FROM Win32_OperatingSystem");

                ManagementObjectSearcher s2 = new ManagementObjectSearcher(scope, wqlQuery);

                foreach (ManagementObject x in s2.Get())
                {
                    version.Add(x["Caption"].ToString() + x["Version"].ToString());
                }
            }
            catch (System.UnauthorizedAccessException e) { return "Noone is logged on."; }
            if (version.Count > 0)
                return version[0];
            else
                return "";

        }

        public void SendEmail(string server, int port, string from, string to, string subject, string message)
        {
            MailMessage email = new MailMessage(from, to, subject, message);
            SmtpClient client = new SmtpClient(server, port);

            try
            {
                client.Send(email);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in CreateTestMessage1(): {0}",
                      ex.ToString());
            }
        }

        public void SendEmail(string server, int port, string from, string to, string subject, string message, string fromPassword)
        {
            MailMessage email = new MailMessage(from, to, subject, message);
            SmtpClient client = new SmtpClient(server, port);
            NetworkCredential cred = new NetworkCredential(from, fromPassword);
            try
            {
                client.Credentials = cred;
               // client.EnableSsl = true;
                client.Send(email);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in CreateTestMessage1(): {0}",
                      ex.ToString());
            }
        }
    }
}

