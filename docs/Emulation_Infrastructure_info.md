## Emulation Infrastructure

### Attacker Information

| System        | IP Address          | Version          | username/password |
|:-------------|:------------------|:------------------|:------------------|
| Kali   | 10.0.0.101 | 2025.1  | kali/kali |
| Parrot OS   | 10.0.0.102 | 6.3 | --- |

1. **Kali Attack Platform**: The Kali system has the Apache service enabled to simulate a phishing website attack. On the desktop, there are implants generated using the Sliver command for both Windows and Linux, which can be directly used for testing.
    - C2 Framework
        - [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
        - [Sliver Framework](https://sliver.sh/)
    - Other tools
        - [atomic-red-team](https://github.com/redcanaryco/atomic-red-team)

Running the `msfconsole` command in the Kali terminal allows you to use the Metasploit framework, and running `sliver` or `sliver-server` enables you to use the Sliver framework.

2. **Parrot Attack Platform**: Parrot OS has a similar configuration to Kali OS.


### Firewall Information

| System        | IP Address          | Version          | username/password |
|:-------------|:------------------|:------------------|:------------------|
| pfSense   | 192.168.100.63 |  CE-2.6.0   |  --- |

The firewall configuration is as follows:

| Interface        | IP Address          | Related Host          | 
|:-------------|:------------------|:------------------|
| WAN(wan) -> em0   | 192.168.100.63/24 |  firewall-pfSense   |
| LAN(lan) -> em1   | 192.168.56.1/24 |  victim-Windows10,victim-Ubuntu,victim-macOS   |
| OPT1(opt1) -> em2   | 10.0.0.1/24 |  attacker-Kali,attacker-Windows10,DNS_server-Debian   |

### DNS_server Information

| System        | IP Address          | Version          | username/password |
|:-------------|:------------------|:------------------|:------------------|
| Debian   | 10.0.0.201 | 12.9.0  | server/123456  |

We have configured a DNS server using Debian. This server is intended to simulate a scenario in which victim hosts download malicious files to their local systems by accessing a domain name. Additionally, the DNS server can be used to monitor traffic, facilitating subsequent analysis.<br>
You can simulate the attack process of downloading the implant to the local system on the victim-Windows 10 machine by accessing the phishing website through a browser and visiting the specified domain name `sliver.labnet.local`.


### Victim information

| System        | IP Address          | Version          | username/password |
|:-------------|:------------------|:------------------|:------------------|
| Windows10   | 192.168.56.101 | Enterprise 22H2 | victim/123456 |
| Ubuntu   | 192.168.56.102 | 22.04 | victim/123456 |
| macOS   | 192.168.56.103 | Monterey 12.0 | victim/123456 |
