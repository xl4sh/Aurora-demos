# Aurora Executor Attacker Environment Setup Guide

This document provides step-by-step instructions to configure the Kali Linux environment for executing the Aurora Executor attack script.

---

## System Overview
- **Name**: Aurora-executor-attacker-kali  
- **Description**: Kali environment for attack simulation  
- **Credentials**:  
  - Username: `kali`  
  - Password: `kali`  
- **OS Details**:  
  ```bash
  Distributor ID: Kali
  Description:    Kali GNU/Linux Rolling
  Release:        2025.1
  Codename:       kali-rolling

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
# Validated Versions: questionary-2.1.0  rich-14.0.0  pymetasploit3-1.0.6  sliver-py-0.0.19
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


