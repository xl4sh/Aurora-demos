The following attack chains are generated to mimic the attack behaviors in report.


## SAM_password_hash_cred_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 5e9f7c5a-1d2b-9f4e-8a4d-3f7a6c2e5e9f | Dump Password Hashes | The `hashdump` command extracts password hashes from the SAM database. |

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

## custom_payload_execution-6
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a91f6876-82a0-4692-8eb7-cc7d9f6a4136 | Windows Inject PE Files, Reverse TCP Stager (IPv6) | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Connect back to the attacker over IPv6 |

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

## meterpreter_executor-7
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| a4fd7b18-bd7b-40fb-bff4-5c15fbd71ba5 | Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock) | This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets the Pure-FTPd FTP server when it has been compiled with the --with-extauth flag and an external Bash script is used for authentication. If the server is not set up this way, the exploit will fail, even if the version of Bash in use is vulnerable. |
| ce80eefc-38d8-466f-aa39-5eab6752b330 | Linux Mettle x86, Reverse TCP Stager | Inject the mettle server payload (staged).<br>Connect back to the attacker |

## hidden_bind_ipknock_tcp-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c8434dc6-4215-4f38-978b-6599eff9a869 | VNC Server (Reflective Injection), Hidden Bind TCP Stager | Inject a VNC Dll via a reflective loader (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |

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
