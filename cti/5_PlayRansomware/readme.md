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

## device_config_modified-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| e8d934bc-1b12-4460-87b7-b268a63e3a6d | Disable Input Devices | The `uictl` command disables keyboard/mouse input devices for defense evasion. |

## system_logoff-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 1976d04c-2f09-4d33-bbff-5fbabf4e0922 | Command Shell, Bind SSM (via AWS API) | Creates an interactive shell using AWS SSM |
| 5a282e50-86ff-438d-8cef-8ae01c9e62e1 | Reboot System via `poweroff` - FreeBSD | This test restarts a FreeBSD system using `poweroff`. |

## arp_cache_info_printed-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| bb4c5c7b-83b7-48f1-88b4-9f2290379aee | Windows Execute Command | Execute an arbitrary command |
| 2d5a61f5-0447-4be4-944a-1f8530ed6574 | Remote System Discovery - arp | Identify remote systems via arp. <br><br>Upon successful execution, cmd.exe will execute arp to list out the arp cache. Output will be via stdout. |

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

## current_directory_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| bb2176c4-855e-4b52-ab03-5fe2e58d8129 | Build DLL Sliver implant | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 7480189e-1a4b-45f5-b225-c102915f7262 | Simulate the victim download a file on its machine | This step simulates the victim accidentally downloads a malicious file by clicking a link. |
| 5b852063-ca39-4600-b246-024897721010 | Simulate the victim execute a DLL file on its machine | This step simulates the victim executes a DLL file on its machine. |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 36b514af-486f-44ad-9f56-09c9d904851d | Get Current Working Directory | The `pwd` command returns the current working directory of the remote system. It helps to determine the current directory where commands are being executed on the remote machine, which is crucial for file management and executing further commands. The command includes flags for setting a timeout. |

## system_command_executed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 08f66886-0e96-455b-be31-b0af37db8e23 | Set a universal payload handler using MSF exploit/multi/handler module | In Metasploit, the exploit/multi/handler module is essentially a universal payload handler.<br>Unlike most exploit modules in Metasploit that target specific vulnerabilities, multi/handler does not exploit a particular service or software.<br>Instead, its main purpose is to listen for incoming connections from payloads that you have already delivered to a target by some other means. |
| 0e67b73a-9927-43e1-8f64-04d38f1db57d | Build Sliver implant (for Windows) | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 19301991-c518-46ca-a622-378e1be4f1ad | Simulate the victim download and execute malicious payload file as Admin (Root) | None |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| 861580a4-aad7-4269-94ea-43f3f775423d | Metasploit Payload Execution using Sliver | The command is used within a Sliver session to execute a Metasploit payload in the current process. It allows users to specify various options such as the encoder type, number of encoding iterations, listening host and port, payload type, and command timeout. By default, it uses the "meterpreter_reverse_https" payload, listens on port 4444, and has a timeout of 60 seconds. This command is typically used for penetration testing and security assessments to deploy payloads on target systems. |
| b9fe1645-bc7e-4743-86dc-7dbee3431e16 | Execute Payload windows-meterpreter_reverse_http | None |
| f5d7e9a1-2b3c-4d5e-8f6a-7b8c9d0e1f2a | Execute System Command | Executes a system command on the remote host through Meterpreter. |

## backup_files_deleted-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| bb4c5c7b-83b7-48f1-88b4-9f2290379aee | Windows Execute Command | Execute an arbitrary command |
| 6b1dbaf6-cc8a-4ea6-891f-6058569653bf | Windows - Delete Backup Files | Deletes backup files in a manner similar to Ryuk ransomware. Upon exection, many "access is denied" messages will appear as the commands try<br>to delete files from around the system. |

## custom_payload_execution-10
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| 8d288122-7bc5-4b42-b334-3cc9d6d35f99 | Custom Payload | Use custom string or file as payload. Set either PAYLOADFILE orPAYLOADSTR. |

## file_info_known-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| bb2176c4-855e-4b52-ab03-5fe2e58d8129 | Build DLL Sliver implant | The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine. |
| 7480189e-1a4b-45f5-b225-c102915f7262 | Simulate the victim download a file on its machine | This step simulates the victim accidentally downloads a malicious file by clicking a link. |
| 5b852063-ca39-4600-b246-024897721010 | Simulate the victim execute a DLL file on its machine | This step simulates the victim executes a DLL file on its machine. |
| 1f401bbe-de24-41d2-8e34-d026e25bfb94 | Execute a Sliver Implant Payload | Executing a Sliver implant payload will establish a Sliver session. |
| f9c1197c-c5ef-4368-a10c-3a53003dbfbf | Remote Directory Listing | The `ls <remote path>` command lists files and directories in a specified remote path or the current directory if no path is provided. By default, it sorts listings by name in ascending order, but can also sort by size or modified time, with options to reverse the order. The command includes flags for sorting, reversing order, and setting a timeout. |

## command_prompt_executor-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| c1745fd8-3317-4885-a109-1c310971b472 | Unix Command, Generic Command Execution | Executes the supplied command |

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

## payload_executed_as_root-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |

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

## defense_impairment-8
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 9284555a-a59e-4568-bed1-a7138e727dd1 | Unix Command Shell, Bind TCP (via Ruby) | Continually listen for a connection and spawn a command shell via Ruby |
| 6d6d3154-1a52-4d1a-9d51-92ab8148b32e | Reboot Linux Host via Kernel System Request | reboot system via system request seen in Awfulshred wiper. |

## shell_executor-4
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 03a4b465-a3c7-403a-9004-d454a344dd30 | UnrealIRCD 3.2.8.1 Backdoor Command Execution | This module exploits a malicious backdoor that was added to the Unreal IRCD 3.2.8.1 download archive. This backdoor was present in the Unreal3.2.8.1.tar.gz archive between November 2009 and June 12th 2010. |
| 2d8e7dd5-5f1d-4364-b90e-d855118460e0 | Unix Command Shell, Reverse TCP (via Ruby) | Connect back and create a command shell via Ruby |

## meterpreter_executor-13
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| be8e1965-514d-4713-be63-2accf8a6e717 | Intelliants Subrion CMS 4.2.1 - Authenticated File Upload Bypass to RCE | This module exploits an authenticated file upload vulnerability in Subrion CMS versions 4.2.1 and lower. The vulnerability is caused by the .htaccess file not preventing the execution of .pht, .phar, and .xhtml files. Files with these extensions are not included in the .htaccess blacklist, hence these files can be uploaded and executed to achieve remote code execution. In this module, a .phar file with a randomized name is uploaded and executed to receive a Meterpreter session on the target, then deletes itself afterwards. |
| f7991bc7-5d51-4099-912c-efbbd5668508 | PHP Meterpreter, Bind TCP Stager IPv6 | Run a meterpreter server in PHP.<br>Listen for a connection over IPv6 |

## user_info_printed-6
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 291452ab-1bfa-4128-948e-0ded410d268f | DistCC Daemon Command Execution | This module uses a documented security weakness to execute arbitrary commands on any system running distccd. |
| 2d8e7dd5-5f1d-4364-b90e-d855118460e0 | Unix Command Shell, Reverse TCP (via Ruby) | Connect back and create a command shell via Ruby |
| 2a9b677d-a230-44f4-ad86-782df1ef108c | System Owner/User Discovery | Identify System owner or users on an endpoint<br><br>Upon successful execution, sh will stdout list of usernames. |

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

## hidden_bind_ipknock_tcp-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 4185edba-8760-4ff9-b3af-b1ff414b4820 | Windows Command Shell, Hidden Bind TCP Inline | Listen for a connection from certain IP and spawn a command shell.The shellcode will reply with a RST packet if the connections is notcoming from the IP defined in AHOST. This way the port will appearas "closed" helping us to hide the shellcode. |

## pingback_bind_tcp-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| f4ec0745-5845-4d58-993c-c5cc2d922832 | Unix Command Shell, Pingback Bind TCP (via netcat) | Accept a connection, send a UUID, then exit |
