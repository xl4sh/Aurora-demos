# Aurora Executor Attacker Environment Setup Guide

This document provides step-by-step instructions to configure the Kali Linux environment for executing the Aurora Executor attack script.

---

You need to install the tools that will be used by Attack Executor. For now, Attack Executor supports the following tools:
- [Metasploit](#metasploit)
- [Sliver](#sliver)
- Nmap

## Tools Download and Configuration
### Sliver

#### Installation
##### Install Sliver-server
Download sliver-server bin from [their webite](https://github.com/BishopFox/sliver/releases)

```
$ ./sliver-server

sliver > new-operator --name zer0cool --lhost localhost --lport 34567 --save ./zer0cool.cfg
[*] Generating new client certificate, please wait ...
[*] Saved new client config to: /Users/zer0cool/zer0cool.cfg

sliver > multiplayer --lport 34567
[*] Multiplayer mode enabled!
```

Then, modify the related entries in `config.ini`:
```
[sliver]
client_config_file = /home/user/Downloads/zer0cool.cfg
```

### Metasploit

#### Installation
##### Install Metasploit

```
$ msfconsole
msf> load msgrpc [Pass=yourpassword]
[*] MSGRPC Service:  127.0.0.1:55552 
[*] MSGRPC Username: msf
[*] MSGRPC Password: glycNshR
[*] Successfully loaded plugin: msgrpc
```

Then, modify the related entries in `config.ini`:
```
[metasploit]
password = glycNshR
host_ip = 127.0.0.1
listening_port = 55552
```

## Attacker-Kali Overview
- **Name**: Aurora-executor-attacker-kali  
- **Description**: Kali environment for attack simulation  
- **Credentials**:  
  - Username: `kali`  
  - Password: `kali`  
- **OS Details**:  
  ```bash
  Distributor ID:  Kali
  Python-version:  3.13.2
  Release:         2025.1

## Environment Configuration
### 1. Python Virtual Environment Setup
```bash
# Create and activate virtual environment
pip install virtualenv
virtualenv env_aurora-executor
source env_aurora-executor/bin/activate
```

### 2. Install Required Packages
```bash
# Validated Versions: attack-executor==0.1.2 questionary-2.1.0  rich-14.0.0  pymetasploit3-1.0.6  sliver-py-0.0.19
pip install attack-executor
pip install questionary  
pip install rich 
pip install pymetasploit3 
pip install sliver-py 
```
### 3. Modify Configuration File
```bash
[sliver]
client_config_file = /your/sliver/client/config/path  # Update to actual path

[metasploit]
password = your_metasploit_password  # Replace with valid credentials
```
## Execute Attack Script
```bash
# example
python ./results/execution_keyboard_input_simulated-3.py
```


