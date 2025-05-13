The following attack chains are generated to mimic the attack behaviors in report.


## system_logoff-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 3672e2fd-0ab7-4f50-8a7e-4e3e87c29d5b | Unix Command Shell, Reverse TCP (via jjs) | Connect back and create a command shell via jjs |
| 5a282e50-86ff-438d-8cef-8ae01c9e62e1 | Reboot System via `poweroff` - FreeBSD | This test restarts a FreeBSD system using `poweroff`. |

## arp_cache_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 2d5a61f5-0447-4be4-944a-1f8530ed6574 | Remote System Discovery - arp | Identify remote systems via arp. <br><br>Upon successful execution, cmd.exe will execute arp to list out the arp cache. Output will be via stdout. |

## credentials_sprayed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 5ccf4bbd-7bf6-43fc-83ac-d9e38aff1d82 | WinPwn - DomainPasswordSpray Attacks | DomainPasswordSpray Attacks technique via function of WinPwn |

## process_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 3b3809b6-a54b-4f5b-8aff-cb51f2e97b34 | Process Discovery - Get-Process | Utilize Get-Process PowerShell cmdlet to identify processes.<br><br>Upon successful execution, powershell.exe will execute Get-Process to list processes. Output will be via stdout. |

## setgid_files_info_printed-13
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| d16c7acf-4b6a-44cc-b4ba-e7f99e08485e | Unix Command Shell, Reverse TCP (via netcat) | Creates an interactive shell via netcat |
| 3fb46e17-f337-4c14-9f9a-a471946533e2 | Do reconnaissance for files that have the setgid bit set | This test simulates a command that can be run to enumerate files that have the setgid bit set |

## bind_named_pipe_listener-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| bf2749bc-5b6e-4b40-8766-60702c48d56b | Unix Command Shell, Bind TCP (via BusyBox telnetd) | Listen for a connection and spawn a command shell via BusyBox telnetd |

## kernel_info_printed-12
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 1c320bac-f9e7-4167-8f3c-624eacfbf6db | Unix Command Shell, Bind TCP (via netcat -e) | Listen for a connection and spawn a command shell via netcat |
| 3a53734a-9e26-4f4b-ad15-059e767f5f14 | Current kernel information enumeration | An adversary may want to enumerate the kernel information to tailor their attacks for that particular kernel. The following command will enumerate the kernel information. |

## powershell_executor-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |

## dll_injection-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 21b4475d-e850-44e3-a11b-891de3bfa265 | Reflective DLL Injection, Reverse Ordinal TCP Stager (No NX or Win7) | Inject a DLL via a reflective loader.<br>Connect back to the attacker |

## local_permission_groups_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 0afb5163-8181-432e-9405-4322710c0c37 | Elevated group enumeration using net group (Domain) | Runs "net group" command including command aliases and loose typing to simulate enumeration/discovery of high value domain groups. This<br>test will display some errors if run on a computer not connected to a domain. Upon execution, domain information will be displayed. |

## backup_files_deleted-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 6b1dbaf6-cc8a-4ea6-891f-6058569653bf | Windows - Delete Backup Files | Deletes backup files in a manner similar to Ryuk ransomware. Upon exection, many "access is denied" messages will appear as the commands try<br>to delete files from around the system. |

## custom_payload_execution-7
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| feb6cff9-8bea-4190-9416-643e61ba0357 | Windows shellcode stage, Windows Reverse HTTP Stager (wininet) | Custom shellcode stage.<br>Tunnel communication over HTTP (Windows wininet) |

## system_time_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 1d5711d6-655c-4a47-ae9c-6503c74fa877 | System Time Discovery - PowerShell | Identify the system time via PowerShell. Upon execution, the system time will be displayed. |

## command_prompt_executor-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |

## reverse_tcp_rc4_dns-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 3e1655fb-679b-4aea-b67a-280e131e502f | Windows shellcode stage, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm) | Custom shellcode stage.<br>Connect back to the attacker |

## executable_download_and_execute-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 5785a47d-2b25-4d92-a122-36fbb7cb2764 | Windows Upload/Execute, Reverse TCP Stager (IPv6) | Uploads an executable and runs it (staged).<br>Connect back to the attacker over IPv6 |

## defense_impairment-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 03a4b465-a3c7-403a-9004-d454a344dd30 | UnrealIRCD 3.2.8.1 Backdoor Command Execution | This module exploits a malicious backdoor that was added to the Unreal IRCD 3.2.8.1 download archive. This backdoor was present in the Unreal3.2.8.1.tar.gz archive between November 2009 and June 12th 2010. |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 3672e2fd-0ab7-4f50-8a7e-4e3e87c29d5b | Unix Command Shell, Reverse TCP (via jjs) | Connect back and create a command shell via jjs |
| 6d6d3154-1a52-4d1a-9d51-92ab8148b32e | Reboot Linux Host via Kernel System Request | reboot system via system request seen in Awfulshred wiper. |

## shell_executor-9
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 86bdf2e6-a150-400a-8708-e4158fe8545d | Windows shellcode stage, Reverse TCP Stager (DNS) | Custom shellcode stage.<br>Connect back to the attacker |

## meterpreter_executor-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 7a4b96c1-3eed-4875-8f34-e34e92e455cc | Windows Meterpreter (Reflective Injection), Hidden Bind Ipknock TCP Stager | Inject the Meterpreter server DLL via the Reflective Dll Injection payload (staged). Requires Windows XP SP2 or newer.<br>Listen for a connection. First, the port will need to be knocked fromthe IP defined in KHOST. This IP will work as an authentication method(you can spoof it with tools like hping). After that you could get yourshellcode from any IP. The socket will appear as "closed," thus helping tohide the shellcode |

## user_info_printed-14
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| a4fd7b18-bd7b-40fb-bff4-5c15fbd71ba5 | Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock) | This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets the Pure-FTPd FTP server when it has been compiled with the --with-extauth flag and an external Bash script is used for authentication. If the server is not set up this way, the exploit will fail, even if the version of Bash in use is vulnerable. |
| f74bf7a1-8d6f-491c-9269-59f765649a9d | Linux Command Shell, Reverse TCP Inline | Connect back to attacker and spawn a command shell |
| 2a9b677d-a230-44f4-ad86-782df1ef108c | System Owner/User Discovery | Identify System owner or users on an endpoint<br><br>Upon successful execution, sh will stdout list of usernames. |

## credentials_dumped-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 5c2571d0-1572-416d-9676-812e64ca9f44 | Registry dump of SAM, creds, and secrets | Local SAM (SAM & System), cached credentials (System & Security) and LSA secrets (System & Security) can be enumerated<br>via three registry keys. Then processed locally using https://github.com/Neohapsis/creddump7<br><br>Upon successful execution of this test, you will find three files named, sam, system and security in the %temp% directory. |

## hidden_bind_ipknock_tcp-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 7a4b96c1-3eed-4875-8f34-e34e92e455cc | Windows Meterpreter (Reflective Injection), Hidden Bind Ipknock TCP Stager | Inject the Meterpreter server DLL via the Reflective Dll Injection payload (staged). Requires Windows XP SP2 or newer.<br>Listen for a connection. First, the port will need to be knocked fromthe IP defined in KHOST. This IP will work as an authentication method(you can spoof it with tools like hping). After that you could get yourshellcode from any IP. The socket will appear as "closed," thus helping tohide the shellcode |

## network_share_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 1b0814d1-bb24-402d-9615-1b20c50733fb | Network Share Discovery PowerShell | Network Share Discovery utilizing PowerShell. The computer name variable may need to be modified to point to a different host<br>Upon execution, avalaible network shares will be displayed in the powershell session |

## pingback_bind_tcp-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| f8033234-632f-4f61-bc94-785841a38a03 | Windows x86 Pingback, Reverse TCP Inline | Connect back to attacker and report UUID (Windows x86) |

## vnc_injector-12
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 844841ab-9462-441e-9985-bef329e3d705 | VNC Server (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm) | Inject a VNC Dll via a reflective loader (staged).<br>Connect back to the attacker |
