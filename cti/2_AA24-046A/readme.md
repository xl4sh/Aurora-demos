The following attack chains are generated to mimic the attack behaviors in report.


## host_connectivity_verified_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 58548149-8405-4b97-95ec-dee9679fcba5 | Build Sliver implant (for Linux) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine (Linux). |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 1a9c0b5e-9a8b-2d3c-5f1e-4a7cb6d42e8f | Host Availability Check | The `ping` command tests network connectivity to the target host. |

## arp_cache_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 2d5a61f5-0447-4be4-944a-1f8530ed6574 | Remote System Discovery - arp | Identify remote systems via arp. <br><br>Upon successful execution, cmd.exe will execute arp to list out the arp cache. Output will be via stdout. |

## bind_named_pipe_listener-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| dd19995b-aa55-45db-854f-45f8c91de7f8 | Windows Upload/Execute, Windows x86 Bind Named Pipe Stager | Uploads an executable and runs it (staged).<br>Listen for a pipe connection (Windows x86) |

## file_content_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 7480189e-1a4b-45f5-b225-c102915f7262 | Simulate the victim download a file on its machine | This step simulates the victim accidentally downloads a malicious file by clicking a link. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 5d3a8f1c-7b62-41a3-9c8d-f1e9b3a7c2e1 | Read File Content | The `cat` command reads the contents of a specified file on the remote host through Meterpreter session. |

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

## current_directory_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| bb2176c4-855e-4b52-ab03-5fe2e58d8129 | Build DLL Sliver implant | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 7480189e-1a4b-45f5-b225-c102915f7262 | Simulate the victim download a file on its machine | This step simulates the victim accidentally downloads a malicious file by clicking a link. |
| 5b852063-ca39-4600-b246-024897721010 | Simulate the victim execute a DLL file on its machine | This step simulates the victim executes a DLL file on its machine. |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 36b514af-486f-44ad-9f56-09c9d904851d | Get Current Working Directory | The `pwd` command returns the current working directory of the remote system. It helps to determine the current directory where commands are being executed on the remote machine, which is crucial for file management and executing further commands. The command includes flags for setting a timeout. |

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

## file_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| bb2176c4-855e-4b52-ab03-5fe2e58d8129 | Build DLL Sliver implant | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 7480189e-1a4b-45f5-b225-c102915f7262 | Simulate the victim download a file on its machine | This step simulates the victim accidentally downloads a malicious file by clicking a link. |
| 5b852063-ca39-4600-b246-024897721010 | Simulate the victim execute a DLL file on its machine | This step simulates the victim executes a DLL file on its machine. |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| f9c1197c-c5ef-4368-a10c-3a53003dbfbf | Remote Directory Listing | The `ls <remote path>` command lists files and directories in a specified remote path or the current directory if no path is provided. By default, it sorts listings by name in ascending order, but can also sort by size or modified time, with options to reverse the order. The command includes flags for sorting, reversing order, and setting a timeout. |

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

## file_read-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| a4fd7b18-bd7b-40fb-bff4-5c15fbd71ba5 | Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock) | This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets the Pure-FTPd FTP server when it has been compiled with the --with-extauth flag and an external Bash script is used for authentication. If the server is not set up this way, the exploit will fail, even if the version of Bash in use is vulnerable. |
| 14c31ca2-5b67-4b67-baf9-5468e8b71816 | Linux Read File | Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor |

## file_checksum_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 7480189e-1a4b-45f5-b225-c102915f7262 | Simulate the victim download a file on its machine | This step simulates the victim accidentally downloads a malicious file by clicking a link. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a | File Checksum Calculation | The `checksum` command retrieves hash values of a file for integrity verification. |

## user_info_printed-7
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| c53be697-994f-44ec-b052-3509dda2c489 | Windows Command Shell, Hidden Bind TCP Stager | Spawn a piped command shell (staged).<br>Listen for a connection from a hidden port and spawn a command shell to the allowed host. |
| 6fbc9e68-5ad7-444a-bd11-8bf3136c477e | Enumerate all accounts (Domain) | Enumerate all accounts<br>Upon exection, multiple enumeration commands will be run and their output displayed in the PowerShell session |

## current_path_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d | Print Working Directory | The `pwd` command retrieves the current working directory path on the remote host. |

## working_directory_changed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d | Create Directory | The `mkdir` command creates a new directory on the remote host. |
| 8e2c4d7a-1f3e-4a9b-bc6d-3f7a9b2e1c4a | Change Working Directory | The `cd` command changes the current working directory on the remote host through Meterpreter session. |

## directory_content_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d | Create Directory | The `mkdir` command creates a new directory on the remote host. |
| 6f7a8b9c-0d1e-2f3a-4b5c-6d7e8f9a0b1c | Directory Listing | The `dir` command lists files in a directory (alias for `ls`). |

## credentials_dumped-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| fda40b30-8f0b-438e-ad2d-b7429d1600d5 | Windows Interactive Powershell Session, Bind TCP | Listen for a connection and spawn an interactive powershell session |
| 00e3e3c7-6c3c-455e-bd4b-461c7f0e7797 | WinPwn - passhunt | Search for Passwords on this system using passhunt via WinPwn |
