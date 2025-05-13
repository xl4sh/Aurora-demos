The following attack chains are generated to mimic the attack behaviors in report.


## pe_file_injection-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| fec660ce-9ff7-49ae-b010-92f1845d3d77 | Windows Inject PE Files, Reverse TCP Stager with UUID Support | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Connect back to the attacker with UUID Support |

## host_connectivity_verified_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 58548149-8405-4b97-95ec-dee9679fcba5 | Build Sliver implant (for Linux) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine (Linux). |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 1a9c0b5e-9a8b-2d3c-5f1e-4a7cb6d42e8f | Host Availability Check | The `ping` command tests network connectivity to the target host. |

## system_logoff-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 1976d04c-2f09-4d33-bbff-5fbabf4e0922 | Command Shell, Bind SSM (via AWS API) | Creates an interactive shell using AWS SSM |
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

## setgid_files_info_printed-14
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| a4fd7b18-bd7b-40fb-bff4-5c15fbd71ba5 | Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock) | This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets the Pure-FTPd FTP server when it has been compiled with the --with-extauth flag and an external Bash script is used for authentication. If the server is not set up this way, the exploit will fail, even if the version of Bash in use is vulnerable. |
| 1bde0d9c-1d3d-4394-8bc0-80b43c9790ac | Interact with Established SSH Connection | Interacts with a shell on an established SSH connection |
| 3fb46e17-f337-4c14-9f9a-a471946533e2 | Do reconnaissance for files that have the setgid bit set | This test simulates a command that can be run to enumerate files that have the setgid bit set |

## bind_named_pipe_listener-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 7ec9d8a2-eba7-4bbe-9912-00344b735120 | Windows Inject PE Files, Windows x86 Bind Named Pipe Stager | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Listen for a pipe connection (Windows x86) |

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

## dll_injection-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 42abe56d-e58e-4e81-adad-1cc85732c663 | Reflective DLL Injection, Reverse TCP Stager (No NX or Win7) | Inject a DLL via a reflective loader.<br>Connect back to the attacker (No NX) |

## active_desktop_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 9f3a8b7c-2c41-4a39-c8df-1e9b3a7c2e1 | Get Active Desktop | The `getdesktop` command displays the current active desktop session information. |

## registry_value_write-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 2d3c5f1e-4a7c-b6d4-2e8f-1a9c0b5e9a8b | Registry Modification | The `registry_write` command modifies Windows registry values. |

## desktop_sessions_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 7d5e9f3a-8b2c-41a3-9c8d-f1e9b3a7c2e1 | Enumerate Desktops | The `enumdesktops` command lists available desktop sessions on Windows systems. |

## file_deleted-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| c54557c4-97cd-46d2-b5d7-7f9011de639e | Remove Remote Path | The `rm(remote_path, recursive=False, force=False)` command removes a directory or file(s) from the remote system. Parameters include remote_path (remote path), recursive (recursively remove file(s)), and force (forcefully remove the file(s)). |

## local_permission_groups_info_printed-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 7bfba376-cebc-4094-b1e6-5103b2e83c4e | Execute PowerShell Command | The `powershell.exe` command executes a PowerShell script or command on the remote host. This command is useful for performing system monitoring tasks or gathering information about the processes running on a remote machine. |
| 3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8 | Enumerate Active Directory Groups with Get-AdGroup | The following Atomic test will utilize Get-AdGroup to enumerate groups within Active Directory.<br>Upon successful execution a listing of groups will output with their paths in AD.<br>Reference: https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps |

## custom_payload_execution-6
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a91f6876-82a0-4692-8eb7-cc7d9f6a4136 | Windows Inject PE Files, Reverse TCP Stager (IPv6) | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Connect back to the attacker over IPv6 |

## user_context_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 8d9e0f1a-2b3c-4d5e-6f7a-8b9c0d1e2f3a | User Identity Check | The `getuid` command retrieves the user context of the Meterpreter session. |

## system_time_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 1d5711d6-655c-4a47-ae9c-6503c74fa877 | System Time Discovery - PowerShell | Identify the system time via PowerShell. Upon execution, the system time will be displayed. |

## desktop_context_switched-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 7d5e9f3a-8b2c-41a3-9c8d-f1e9b3a7c2e1 | Enumerate Desktops | The `enumdesktops` command lists available desktop sessions on Windows systems. |
| b5c3d9a2-7e4f-4a1d-8c3b-6f2e5a1d0b9c | Desktop Context Switching | The `setdesktop` command switches between desktop contexts. |

## executable_download_and_execute-6
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| 4997ad3f-6882-417b-8c20-fcc789a9ea2c | PHP Executable Download and Execute | Download an EXE from an HTTP URL and execute it |

## user_activity_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| a7c2e19f-3a8b-41a3-9c8d-f1e9b37d5e9f | Measure User Inactivity | The `idletime` command reports the duration of user inactivity on Windows systems. |

## visual_data_saved-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 7d5e9f3a-8b2c-41a3-9c8d-f1e9b3a7c2e1 | Enumerate Desktops | The `enumdesktops` command lists available desktop sessions on Windows systems. |
| 7d3e9b2a-1c5f-4e8d-a9b7-6f2c4a1e0d9b | Remote Screen Capture | The `screenshare` command captures remote screen content in real time. |

## defense_impairment-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 4b81bcfa-fb0a-45e9-90c2-e3efe5160140 | Disable Remote Desktop Security Settings Through Registry | A modification registry to disable RDP security settings. This technique was seen in DarkGate malware as part of its installation |

## meterpreter_executor-13
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| f7991bc7-5d51-4099-912c-efbbd5668508 | PHP Meterpreter, Bind TCP Stager IPv6 | Run a meterpreter server in PHP.<br>Listen for a connection over IPv6 |

## user_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 406c13e9-da5b-43a4-89af-c9b0efdc3ec2 | PHP CGI Argument Injection | When run as a CGI, PHP up to version 5.3.12 and 5.4.2 is vulnerable to an argument injection vulnerability.  This module takes advantage of the -d flag to set php.ini directives to achieve code execution. <br> From the advisory: "if there is NO unescaped '=' in the query string, the string is split on '+' (encoded space) characters, urldecoded, passed to a function that escapes shell metacharacters (the "encoded in a system-defined manner" from the RFC) and then passes them to the CGI binary." This module can also be used to exploit the plesk 0day disclosed by kingcope and exploited in the wild on June 2013. |
| 9234502a-980c-49a7-8955-1d2c9be61116 | PHP Command, Double Reverse TCP Connection (via Perl) | Creates an interactive shell via perl |
| 2a9b677d-a230-44f4-ad86-782df1ef108c | System Owner/User Discovery | Identify System owner or users on an endpoint<br><br>Upon successful execution, sh will stdout list of usernames. |

## credentials_dumped-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 7bfba376-cebc-4094-b1e6-5103b2e83c4e | Execute PowerShell Command | The `powershell.exe` command executes a PowerShell script or command on the remote host. This command is useful for performing system monitoring tasks or gathering information about the processes running on a remote machine. |
| 0c0f5f06-166a-4f4d-bb4a-719df9a01dbb | WinPwn - Loot local Credentials - Dump SAM-File for NTLM Hashes | Loot local Credentials - Dump SAM-File for NTLM Hashes technique via function of WinPwn |

## hidden_bind_ipknock_tcp-7
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 42941ebf-58c8-4ac3-92a4-bdda208449af | Windows Inject PE Files, Bind IPv6 TCP Stager (Windows x86) | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Listen for an IPv6 connection (Windows x86) |

## network_share_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 1b0814d1-bb24-402d-9615-1b20c50733fb | Network Share Discovery PowerShell | Network Share Discovery utilizing PowerShell. The computer name variable may need to be modified to point to a different host<br>Upon execution, avalaible network shares will be displayed in the powershell session |

## pingback_bind_tcp-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 3014f920-06a4-45e8-863f-6aa4b895e662 | Unix Command Shell, Pingback Reverse TCP (via netcat) | Creates a socket, send a UUID, then exit |

## vnc_injector-7
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 7cdd4cc3-fd60-45df-b949-ade692d3f163 | VNC Server (Reflective Injection), Reverse TCP Stager (No NX or Win7) | Inject a VNC Dll via a reflective loader (staged).<br>Connect back to the attacker (No NX) |
