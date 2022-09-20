## External Recon & Testing
One should gather the probable email addressess of the employees working at XYZ company using the methods given below. It is possible to craft the email address by finding out the domain name and the email format of the company.
- Reconnaissance using the tools given below
  - phonebook.cz
  - theHarvester
  - hunter.io (Paid)
  - linkedin.com (https://gist.github.com/Voker2311/c8ff452fa6631f8aa6e629a33a4aa974)
  - Github & Google dorking
  - Search engines like Bing, Baidu, Google, DuckDuckGo, Yandex
  - dehashed.com (credential stuffing)
  - spiderfoot
  - pastebins
  - ![crosslinked.py](https://github.com/m8sec/CrossLinked)
- Outlook account exploitation
- AWS account exploitation
- Azure AD Enumeration
- Nmap and Nessus services scan
- Known CVEs and vulnerabilities
- OSINT
- Breach Parse by Heath Adams
- Phishing Campaign (if in-scope)
- Github, Gitlab, BitBucket, TFS, SVN enumeration
- Username generation (https://gist.githubusercontent.com/superkojiman/11076951/raw/74f3de7740acb197ecfa8340d07d3926a95e5d46/namemash.py)

## Internal Recon & Testing
- Nmap scans
  - Full port
  - Fast UDP scan
  - Decoys, Fragmented, Timing and Source ports scanning for firewall/IDS evasion
  - Basic TCP
  - Stealth scan (in case of firewall)
  - Services scan
  - Vulners scan
- Nessus scanning
- Domain enumeration using PowerView, BloodHound, ADModule and powercat
- Weak AD Credentials
- PetitPotam unauthenticated NTLM relaying
- samAccountName spoofing (CVE-2021–42278 and CVE-2021–42287)
- LLMNR/NBTNS Poisoning
- ADIDNS wildcard entry for LLMNR spoofing
- MITM attacks like ARP, DHCP spoofing and poisoning
- Zerologon (CVE-2020-1472) (https://github.com/SecuraBV/CVE-2020-1472)
- Anonymous LDAP bind
- Checking for AzureADConnect Sync for dumping domain admin credential.
  - https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/
  - https://blog.xpnsec.com/azuread-connect-for-redteam/
- AdminCount attribute set on common users
- AD Credentials reuse (Location specific)
- SMB Guest session configured
- PrinterBug + Unconstrained Delegation system -> Elevated Access
- goldenPac attack (MS14-068)
- mitm6 attacks & relaying (https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
- Open SMB shares
- SCF/URL/RTF file attack
- Location based password spraying like Mumbai@123, Bangalore@123 and so on.
- Account lockout policy not set for domain accounts
- Users having rights to add computers to domain
- PrintNightmare RCE
- ADCS templates exploitation
- Active Directory Certificate Services (CVE-2022-26923)
- Kerberos attacks
  - Pass The Ticket attack
  - Kerberoasting
  - AS-REP Roasting
  - Golden & Silver Ticket attacks
  - Skeleton Key attack (Persistence)
- Local admin access using weak credentials
- Checking Group Policies
- Checking SYSVOL folder for logon scripts
- DFSCoerce NTLM Relay attack
- WannaCry Ransomware / EternalBlue
  - (https://raw.githubusercontent.com/worawit/MS17-010/master/checker.py)
- Bluekeep RDP Exploit
- Heartbleed SSL check
- Weak credentials against different services like MSSQL, WinRM, RDP, SSH, FTP, etc. (https://github.com/fuzz-security/SuperWordlist)
- Microsoft Follina Phishing attack
- Default userpasses like user:user123, user:user, admin:admin@123 and so on.
- HiveNightmare / Serious SAM
- PowerView enumeration
- Checking weak credentials against VNC, X11, and SNMP
- AnyDesk port 7070 exploitation
- Solarwinds DameWare Remote Control Exploitation
- Log4shell and Spring4shell
- Bloodhound / SharpHound enumeration
- Windows Privilege Escalation
  - Member of Administrators group
  - Service misconfigurations
  - Kernal Exploits - Known CVEs and vulnerabilities
  - Registry Exploits
  - Storage of cleartext credentials
  - Impersonation exploits
  - AV Evasion & AMSI Bypass techniques
- Exploiting services like Redis, Memcache, Oracle, Apache, etc.
- Oracle attacks
  - Oracle TNS Poisoning
  - Brute forcing TNS Listener
  - https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener

When a NTLM authentication is disabled, it is possible to pwn the environment by using the set of impacket tools. (Only if one have valid domain credentials)
- Use of impacket toolkit

Tools for Permissions & ACL Enumeration:
- BloodHound
- ldap-utils
- PowerView
- http://cjwdev.com/Software/ADPermissionsReporter/Download.html

### Hash cracking
- Basic hash cracking using open source wordlists (Seclists,crackstation.net,rockyou.txt)
- Rule based hash cracking
- Mask based hash cracking
  - eg. For Password1, we can set mask to something like: ?u?l?l?l?l?l?l?l?d
  - eg. For Company@123, we can set mask to something like: ?u?l?l?l?l?l?l?1?d?d?d
- Renting GPU servers on Cloud
- Using ![kwprocessor](https://github.com/hashcat/kwprocessor)


### AMSI/AV Bypass techniques
- Modifying couple of function name and parameters in the reverse shell/exploits. If possible, try to create our own reverse shell using C# or C++ to evade Windows Defender or AV.
- https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/
- Use of netcat (In a real world scenario)
- Use of ![GreatSCT](https://github.com/GreatSCT/GreatSCT) toolkit for creating obfuscated payloads

### Post Exploitation:
- PowerShell History file
- Stored Passwords in text and configuration files
- Escalation via WSL (Windows Subsystem for Linux)
- runAs command to use stored credentials on the machine
- Escalation via AutoRun feature
- AlwaysInstalledElevated feature
- Azure Pass-The-Cookie attack (Firefox/Chrome) - Bypassing MFA
- Autologon credentials
- Using Lazagne tool to extract credentials (https://github.com/AlessandroZ/LaZagne)
- regsvc ACL exploit

### Wireless Security
- WEP cracking
- Beacon flood attack
- Deauthentication/Disassociation
- Fake captive portals
- Social Engineering
- WPA2 cracking
- AP-less attacks
