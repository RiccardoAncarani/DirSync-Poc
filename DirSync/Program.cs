using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Principal;
using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Web.Script.Serialization;

namespace DirSync
{
    class Program
    {
        private static ConcurrentDictionary<string, byte> _nullSids;
        private static readonly string[] Props = { "distinguishedname", "samaccounttype", "samaccountname", "dnshostname" };
        private static ConcurrentDictionary<string, string> _guidMap;
        private static ConcurrentDictionary<string, string> _baseGuids;
        private static readonly string AllGuid = "00000000-0000-0000-0000-000000000000";

        static void Main(string[] args)
        {
            string ldapCookie = "adsync-cookie.dat";
            string str_dcName = "dc01.isengard.local";
            bool firstRun = true;

            _nullSids = new ConcurrentDictionary<string, byte>();
            _guidMap = new ConcurrentDictionary<string, string>();
            _baseGuids = new ConcurrentDictionary<string, string>();
            _baseGuids.TryAdd("user", "bf967aba-0de6-11d0-a285-00aa003049e2");
            _baseGuids.TryAdd("computer", "bf967a86-0de6-11d0-a285-00aa003049e2");
            _baseGuids.TryAdd("group", "bf967a9c-0de6-11d0-a285-00aa003049e2");
            _baseGuids.TryAdd("domain", "19195a5a-6da0-11d0-afd3-00c04fd930c9");
            _baseGuids.TryAdd("gpo", "f30e3bc2-9ff0-11d1-b603-0000f80367c1");

            System.DirectoryServices.DirectoryEntry rootDSE = new System.DirectoryServices.DirectoryEntry("LDAP://rootDSE");
            System.Net.NetworkCredential cr = new System.Net.NetworkCredential(@"Administrator", "1qazxsw2..", "isengard.local");
            LdapConnection connection = new LdapConnection(str_dcName);
            connection.Credential = cr;
            connection.Bind();

            DirectorySynchronization sync = new DirectorySynchronization();
            DirectorySearcher src2 = new DirectorySearcher();

            if (File.Exists(ldapCookie))
            {
                byte[] byteCookie = File.ReadAllBytes(ldapCookie);
                sync.ResetDirectorySynchronizationCookie(byteCookie);
                
                firstRun = false;
            }
            src2.DirectorySynchronization = sync;

            foreach (SearchResult res in src2.FindAll())
                {
                    ResultPropertyCollection fields = res.Properties;

                    foreach (String ldapField in fields.PropertyNames)
                    {

                        foreach (Object myCollection in fields[ldapField])
                        {
                        if (!firstRun)
                        {
                            if (ldapField == "distinguishedname")
                            {
                                Console.WriteLine(String.Format("[+] DN = {0}", myCollection));

                            }

                            if (ldapField == "ntsecuritydescriptor")
                            {
                                Console.WriteLine("[+] Detected ACL Change: ");
                                var aces = new List<ACL>();
                                var newDescriptor = new ActiveDirectorySecurity();
                                newDescriptor.SetSecurityDescriptorBinaryForm((byte[])myCollection);
                               // todo add owner 

                                foreach (ActiveDirectoryAccessRule ace in newDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                                {
                                    //Ignore null aces
                                    if (ace == null)
                                        continue;

                                    //Ignore Deny aces
                                    if (!ace.AccessControlType.Equals(AccessControlType.Allow))
                                        continue;

                                    //Resolve the principal in the ACE
                                    var principal = GetAcePrincipal(ace, "isengard.local");
                                    string name = new System.Security.Principal.SecurityIdentifier(principal).Translate(typeof(System.Security.Principal.NTAccount)).ToString();

                                    //If its null, we don't care so move on
                                    if (principal == null)
                                        continue;

                                   
                                    //Interesting Domain ACEs - GenericAll, WriteDacl, WriteOwner, Replication Rights, AllExtendedRights
                                    var rights = ace.ActiveDirectoryRights;
                                    var objectAceType = ace.ObjectType.ToString();

                                    if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                                    {
                                        if (objectAceType == AllGuid || objectAceType == "")
                                        {
                                            aces.Add(new ACL
                                            {
                                                AceType = "",
                                                RightName = "GenericAll",
                                                PrincipalName = name,
                                                PrincipalType = principal
                                            });
                                        }
                                        //GenericAll includes every other flag, so continue here so we don't duplicate privs
                                        continue;
                                    }

                                    if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                                    {
                                        aces.Add(new ACL
                                        {
                                            AceType = "",
                                            RightName = "WriteDacl",
                                            PrincipalName = name,
                                            PrincipalType = principal
                                        });
                                    }

                                    if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                                    {
                                        aces.Add(new ACL
                                        {
                                            AceType = "",
                                            RightName = "WriteOwner",
                                            PrincipalName = name,
                                            PrincipalType = principal
                                        });
                                    }

                                    if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                                    {
                                        if (objectAceType == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
                                        {
                                            aces.Add(new ACL
                                            {
                                                AceType = "GetChanges",
                                                RightName = "ExtendedRight",
                                                PrincipalName = name,
                                                PrincipalType = principal
                                            });
                                        }
                                        else if (objectAceType == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
                                        {
                                            aces.Add(new ACL
                                            {
                                                AceType = "GetChangesAll",
                                                RightName = "ExtendedRight",
                                                PrincipalName = name,
                                                PrincipalType = principal
                                            });
                                        }
                                        else if (objectAceType == AllGuid || objectAceType == "")
                                        {
                                            aces.Add(new ACL
                                            {
                                                AceType = "All",
                                                RightName = "ExtendedRight",
                                                PrincipalName = name,
                                                PrincipalType = principal
                                            });
                                        }
                                    }
                                }
                                

                                foreach (var ace in aces)
                                {
                                    
                                    Console.WriteLine(String.Format("[+] {0} has {1}", ace.PrincipalName, ace.RightName));
                                }
                                ;
                            }


                            if (ldapField == "useraccountcontrol")
                            {
                                Console.WriteLine(String.Format("[+] UAC edited: {0}", myCollection));
                            }
                        }
                           
                        }
                    }
                }

            File.WriteAllBytes(ldapCookie, sync.GetDirectorySynchronizationCookie());



        }

        private static string GetAcePrincipal(ActiveDirectoryAccessRule rule, string domainName)
        {
            return rule.IdentityReference.Value;
        }
    }
}
