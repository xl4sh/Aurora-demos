The following attack chains are generated to mimic the attack behaviors in report.


## system_logoff-6
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 8887a435-939a-4d9b-bcdc-75eb3877bca9 | Samba "username map script" Command Execution | This module exploits a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3 when using the non-default "username map script" configuration option. By specifying a username containing shell meta characters, attackers can execute arbitrary commands. <br> No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication! |
| 22589e32-1738-4b8c-8251-314ecb823ed1 | Unix Command Shell, Reverse TCP SSL (via php) | Creates an interactive shell via php, uses SSL |
| 5a282e50-86ff-438d-8cef-8ae01c9e62e1 | Reboot System via `poweroff` - FreeBSD | This test restarts a FreeBSD system using `poweroff`. |

## credentials_sprayed-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |
| 5ccf4bbd-7bf6-43fc-83ac-d9e38aff1d82 | WinPwn - DomainPasswordSpray Attacks | DomainPasswordSpray Attacks technique via function of WinPwn |

## process_info_printed-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 08325861-d5ca-40c3-b54a-cdc62a8adce3 | Windows Interactive Powershell Session, Reverse TCP | Listen for a connection and spawn an interactive powershell session |
| 3b3809b6-a54b-4f5b-8aff-cb51f2e97b34 | Process Discovery - Get-Process | Utilize Get-Process PowerShell cmdlet to identify processes.<br><br>Upon successful execution, powershell.exe will execute Get-Process to list processes. Output will be via stdout. |

## setgid_files_info_printed-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| b78c256a-b1e7-4e99-9658-371bbcdbdd27 | Advantech Switch Bash Environment Variable Code Injection (Shellshock) | This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets the 'ping.sh' CGI script, accessible through the Boa web server on Advantech switches. This module was tested against firmware version 1322_D1.98. |
| 5d4dafd4-bbd0-47b6-a1b1-511271277fcd | Unix Command Shell, Double Reverse TCP SSL (openssl) | Creates an interactive shell through two inbound connections |
| 3fb46e17-f337-4c14-9f9a-a471946533e2 | Do reconnaissance for files that have the setgid bit set | This test simulates a command that can be run to enumerate files that have the setgid bit set |

## bind_named_pipe_listener-2
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| dd19995b-aa55-45db-854f-45f8c91de7f8 | Windows Upload/Execute, Windows x86 Bind Named Pipe Stager | Uploads an executable and runs it (staged).<br>Listen for a pipe connection (Windows x86) |

## powershell_executor-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |

## dll_injection-11
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 911b568f-1fd4-4cc0-8ff0-5cf75f020347 | Reflective DLL Injection, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm) | Inject a DLL via a reflective loader.<br>Connect back to the attacker |

## local_permission_groups_info_printed-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |
| 3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8 | Enumerate Active Directory Groups with Get-AdGroup | The following Atomic test will utilize Get-AdGroup to enumerate groups within Active Directory.<br>Upon successful execution a listing of groups will output with their paths in AD.<br>Reference: https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps |

## custom_payload_execution-3
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 23817d13-8940-4451-9ad7-cd7696a3ebbe | Windows Inject PE Files, Reverse All-Port TCP Stager | Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PEloader will execute the pre-mapped PE image starting from the address of entry after performing image baserelocation and API address resolution. This module requires a PE file that contains relocation data and avalid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacksare not currently supported. Also PE files which use resource loading might crash.Try to connect back to the attacker, on all possible ports (1-65535, slowly) |

## system_time_info_printed-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |
| 1d5711d6-655c-4a47-ae9c-6503c74fa877 | System Time Discovery - PowerShell | Identify the system time via PowerShell. Upon execution, the system time will be displayed. |

## executable_download_and_execute-9
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 840cc1b6-fa0f-4518-90f4-bb61b9ffd30a | Windows Upload/Execute, Reverse TCP Stager (No NX or Win7) | Uploads an executable and runs it (staged).<br>Connect back to the attacker (No NX) |

## shell_executor-10
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| b78c256a-b1e7-4e99-9658-371bbcdbdd27 | Advantech Switch Bash Environment Variable Code Injection (Shellshock) | This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets the 'ping.sh' CGI script, accessible through the Boa web server on Advantech switches. This module was tested against firmware version 1322_D1.98. |
| 5d4dafd4-bbd0-47b6-a1b1-511271277fcd | Unix Command Shell, Double Reverse TCP SSL (openssl) | Creates an interactive shell through two inbound connections |

## meterpreter_executor-8
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| ed8ced52-3222-4455-b7ff-0e6617712b97 | Windows Meterpreter (skape/jt Injection), Bind TCP Stager (No NX or Win7) | Inject the meterpreter server DLL (staged).<br>Listen for a connection (No NX) |

## user_info_printed-10
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| 291452ab-1bfa-4128-948e-0ded410d268f | DistCC Daemon Command Execution | This module uses a documented security weakness to execute arbitrary commands on any system running distccd. |
| 9573e724-5a54-4ee1-9104-6fdc396f8e5b | Unix Command Shell, Reverse TCP SSL (telnet) | Creates an interactive shell via mkfifo and telnet.This method works on Debian and other systems compiledwithout /dev/tcp support. This module uses the '-z'option included on some systems to encrypt using SSL. |
| 2a9b677d-a230-44f4-ad86-782df1ef108c | System Owner/User Discovery | Identify System owner or users on an endpoint<br><br>Upon successful execution, sh will stdout list of usernames. |

## credentials_dumped-5
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |
| 00e3e3c7-6c3c-455e-bd4b-461c7f0e7797 | WinPwn - passhunt | Search for Passwords on this system using passhunt via WinPwn |

## hidden_bind_ipknock_tcp-12
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 54e18fbc-1fdb-4f44-a7e5-cc5c7d255426 | Windows shellcode stage, Bind TCP Stager with UUID Support (Windows x86) | Custom shellcode stage.<br>Listen for a connection with UUID Support (Windows x86) |

## network_share_info_printed-6
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| a633bbd8-9c6b-4f3c-9c03-7b0b4a6348f5 | Windows Interactive Powershell Session, Reverse TCP SSL | Listen for a connection and spawn an interactive powershell session over SSL |
| 1b0814d1-bb24-402d-9615-1b20c50733fb | Network Share Discovery PowerShell | Network Share Discovery utilizing PowerShell. The computer name variable may need to be modified to point to a different host<br>Upon execution, avalaible network shares will be displayed in the powershell session |

## vnc_injector-1
Among our available attack actions, this attack chain most closely matches the CTI report. The following table shows the specific attack actions in the chain whose tactics, techniques, and procedures (TTPs) are mentioned in the original attack report.

| uuid | name | description |
| --- | --- | --- |
| de6091de-bce3-456d-bf1e-0a88936f06ed | ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability | This module exploits a vulnerability found in ManageEngine Desktop Central 9. When uploading a 7z file, the FileUploadServlet class does not check the user-controlled ConnectionId parameter in the FileUploadServlet class. This allows a remote attacker to inject a null bye at the end of the value to create a malicious file with an arbitrary file type, and then place it under a directory that allows server-side scripts to run, which results in remote code execution under the context of SYSTEM. <br> Please note that by default, some ManageEngine Desktop Central versions run on port 8020, but older ones run on port 8040. Also, using this exploit will leave debugging information produced by FileUploadServlet in file rdslog0.txt. <br> This exploit was successfully tested on version 9, build 90109 and build 91084. |
| 1d7f3941-530e-4692-a2fd-1382a59e3025 | VNC Server (Reflective Injection), Reverse HTTP Stager Proxy | Inject a VNC Dll via a reflective loader (staged).<br>Tunnel communication over HTTP |
