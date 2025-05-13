The following attack chains are generated to mimic the attack behaviors in report.


## host_connectivity_verified_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 58548149-8405-4b97-95ec-dee9679fcba5 | Build Sliver implant (for Linux) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine (Linux). |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 1a9c0b5e-9a8b-2d3c-5f1e-4a7cb6d42e8f | Host Availability Check | The `ping` command tests network connectivity to the target host. |

## system_logoff-15
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 3d8c25b5-7ff5-4c9d-b21f-85ebd06654a4 | Logoff System - Windows | This test performs a Windows system logoff as seen in [dcrat backdoor capabilities](https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor) |

## arp_cache_info_printed-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 2074d817-7819-401b-b552-1045672f77f3 | Execute Command (cmd.exe) | The `cmd.exe` command executes a Windows command. It runs the specified command on the remote host and returns the result. This command is useful for performing various system tasks. |
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

## bind_named_pipe_listener-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| dd19995b-aa55-45db-854f-45f8c91de7f8 | Windows Upload/Execute, Windows x86 Bind Named Pipe Stager | Uploads an executable and runs it (staged).<br>Listen for a pipe connection (Windows x86) |

## powershell_executor-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |

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

## local_permission_groups_info_printed-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |
| 3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8 | Enumerate Active Directory Groups with Get-AdGroup | The following Atomic test will utilize Get-AdGroup to enumerate groups within Active Directory.<br>Upon successful execution a listing of groups will output with their paths in AD.<br>Reference: https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps |

## backup_files_deleted-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 6b1dbaf6-cc8a-4ea6-891f-6058569653bf | Windows - Delete Backup Files | Deletes backup files in a manner similar to Ryuk ransomware. Upon exection, many "access is denied" messages will appear as the commands try<br>to delete files from around the system. |

## custom_payload_execution-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 15609911-8ed5-43b7-a1ba-82f817ed48cb | Windows Inject PE Files, Bind TCP Stager (RC4 Stage Encryption, Metasm) | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Listen for a connection |

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

## executable_download_and_execute-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| dd19995b-aa55-45db-854f-45f8c91de7f8 | Windows Upload/Execute, Windows x86 Bind Named Pipe Stager | Uploads an executable and runs it (staged).<br>Listen for a pipe connection (Windows x86) |

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

## shell_executor-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 4e9c0343-574c-4eb5-8b42-163eedd0b0cc | Windows Command Shell, Bind TCP Inline | Listen for a connection and spawn a command shell |

## meterpreter_executor-8
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| ed8ced52-3222-4455-b7ff-0e6617712b97 | Windows Meterpreter (skape/jt Injection), Bind TCP Stager (No NX or Win7) | Inject the meterpreter server DLL (staged).<br>Listen for a connection (No NX) |

## user_info_printed-7
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 6fbc9e68-5ad7-444a-bd11-8bf3136c477e | Enumerate all accounts (Domain) | Enumerate all accounts<br>Upon exection, multiple enumeration commands will be run and their output displayed in the PowerShell session |

## credentials_dumped-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 7bfba376-cebc-4094-b1e6-5103b2e83c4e | Execute PowerShell Command | The `powershell.exe` command executes a PowerShell script or command on the remote host. This command is useful for performing system monitoring tasks or gathering information about the processes running on a remote machine. |
| 0c0f5f06-166a-4f4d-bb4a-719df9a01dbb | WinPwn - Loot local Credentials - Dump SAM-File for NTLM Hashes | Loot local Credentials - Dump SAM-File for NTLM Hashes technique via function of WinPwn |

## hidden_bind_ipknock_tcp-12
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 54e18fbc-1fdb-4f44-a7e5-cc5c7d255426 | Windows shellcode stage, Bind TCP Stager with UUID Support (Windows x86) | Custom shellcode stage.<br>Listen for a connection with UUID Support (Windows x86) |

## network_share_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 1b0814d1-bb24-402d-9615-1b20c50733fb | Network Share Discovery PowerShell | Network Share Discovery utilizing PowerShell. The computer name variable may need to be modified to point to a different host<br>Upon execution, avalaible network shares will be displayed in the powershell session |
