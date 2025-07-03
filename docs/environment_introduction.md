# Introduction to the emulateion environment

## Deploy the attacker machine
The attacker machine should be equipped with the necessary attack tools.

### Pull the pre-configured VM image
We’ve prepared pre-configured attacker machine for you! You can download and deploy it directly from [here](https://drive.google.com/file/d/1LH237s_uxqT50KrQeBPlTo7rok1m7Q7O/view?usp=drive_link) or using this command:
```bash
# Windows
python pull.py -k attacker -d download -vm C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe --url_table docs\url_table.csv -nr

#Linux
python pull.py -k attacker -d download -vm /usr/bin/VBoxManage --url_table docs/url_table.csv -nr
```

### Install the attack equipments by yourself
We use [Attack Executor](https://github.com/LexusWang/attack_executor) to execute the attack actions provided by different attack tools.
Detailed configuration steps are documented in [Guide](./docs/attacker_environment_setup_guide.md).

If you find the step-by-step configuration cumbersome, you can use our provided [script](https://github.com/LexusWang/Aurora-demos/blob/main/docs/auto_deploy.sh) to install the environment required to execute the script with a single click.

```bash
# Kali attacker
source auto_deploy.sh
```

## Deploy the victim machines
Running `pull.py` on the attack chain YML file automatically downloads and deploys the corresponding victim machines.

``` bash
## Prohibit repeated VM downloading
python pull.py -p #yml_file_path -d #storage_path -vm #VBoxManage.exe_path --url_table #url_table_path -nr -firewall #yes/no
```
- `-p #yml_file_path`：The path of the attack chain `.yml` file;  
- `-d #storage_path`：The storage path of the downloaded VM file;  
- `-vm #VBoxManage.exe_path`：The path of installed VirtualBox executable file (`VBoxManage.exe`);  
- `--url_table #url_table_path`：The path of the Download Link mapping table (url_table.csv);
- `-nr`：Prohibiting duplicate deployment;
- `-r`：Allowing duplicate downloads;
- `-firewall #yes/no`：Use pfSense firewall to isolate the attack host and the target host.  
- `-k #search_key`：Instead of using the `.yml` file of the attack chain, directly search for the target machine or attack machine using `search_key` 

Notes:
- Two download modes are supported:
  - No duplication (`-nr`): If the VM image file already exists, it will skip the downloading and directly proceed with deployment.
  - Allow duplications (`-r`): VM image files will be automatically redownloaded and renamed to avoid conflicts.

- During initial deployment, the VM will not start automatically, allowing users to modify configurations before first startup.

- By default, two network adapters will be configured for each VM: one in NAT mode and the other in Host-only mode. Make sure the required network is configured in VirtualBox; otherwise, the VM may fail to start.


<!-- Example:If you don't want to allow repeated downloads of the attack chain "examples\access_encrypted_edge_credentials\attack_chain.yml" corresponding to the range. You can use  -->
Example: Deploy the emulation environments of the attack chain `attack_chains\keyboard_input_simulated-3\attack_chain.yml` on Windows:
``` bash
python pull.py -p attack_chains\keyboard_input_simulated-3\attack_chain.yml -d download -vm C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe --url_table docs\url_table.csv -nr -firewall no
```
If the VM image file has been downloaded before, it will display:
<p align="center">

<img src="../images/No_repeat.png" alt="request" width="1200"/>

</p>
Entering "yes" will directly start the corresponding virtual machine.
On the contrary, if duplication is allowed, the VM image file will be redownloaded and renamed to avoid conflicts.

<br>

<!-- ``` bash
python pull.py -p examples\access_encrypted_edge_credentials\attack_chain.yml -d download -vm C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe --url_table docs\url_table.csv -nr -firewall yes
``` -->
If you want to use firewall for isolation. Just set `-firewall` as `yes`. 
When using pfsense, the configuration interface is as follows:
<p align="center">

<img src="../images/pfsense.png" alt="pfsense set" width="1200"/>

</p>
⚠️ Please note that if you want to deploy a firewall, two host-only network adapters need to be set up in VirtualBox.
Meanwhile, it is recommended to turn off the NAT network adapters (otherwise all VMs can connect directly).

<br>
In addition to building the VM from the `attack_chain.yml` files, you can also pull and deploy the VMs in this table by using the `-k` flag. It will search for the corresponding virtual machine through search_key.

For example:
``` bash
python pull.py -k MacOS -d download -vm C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe --url_table docs\url_table.csv -nr
```

## Details of the pre-configured virtual machines

| os_type | name | CVE | download_url |
|:--:|----|----|----|
| Linux | Metasploitable | CVE-2007-2447 & CVE-2004-2687 | https://drive.google.com/file/d/1b2WujghpCcGOtjMmi98dhgVca1Pujzn7/view?usp=sharing |
| Linux | metasploitable-linux-2.0.0 | CVE-2012-1823 & CVE-2010-2075 | https://drive.google.com/file/d/1e-wXMpnQPNEED9ouXXDVjo_Fjk4qDSRO/view?usp=sharing |
| Linux | doubletrouble | CVE-2020-7246 | https://drive.google.com/file/d/1lY1xGt_JDm2eqPNIrJIUuNcUCT1RmmC-/view?usp=sharing |
| Linux | VulnCMS | CVE-2015-7297 & CVE-2018-7600 & CVE-2021-4034 | https://drive.google.com/file/d/1dWc9EzfEf02Urk6-Z_mefzLRL3cX4e0r/view?usp=sharing |
| Linux | TechSupport-Clone | CVE-2018-19422 | https://drive.google.com/file/d/1K5NKtJ3eL1T5q5_P0y_DRsXuxd60kJam/view?usp=sharing |
| Linux | hacksudo-FOG | CVE-2018-1000094 | https://drive.google.com/file/d/1d6zHEu_lPigzkd5A8ZxQqcNhqwgpaJVv/view?usp=sharing |
| Linux | Aragog-1.0.2 | CVE-2020-25213 | https://drive.google.com/file/d/1nj0RMxUL0SpZtMKKwMbnqDmNmT9lir2K/view?usp=sharing |
| Linux | hacksudo---Thor | CVE-2014-6271 | https://drive.google.com/file/d/1jJ4YGa_BQezQEkrFDEAQugCZZVmglhg-/view?usp=sharing |
| Linux | blogger | CVE-2020-24186 | https://drive.google.com/file/d/1fjUTVTjSCTnEDNsHBpPiKNb0YPzhGEx4/view?usp=sharing |
| Linux | devguru | CVE-2020-14144 | https://drive.google.com/file/d/1yMomEC_NGjW55ljwg7vN12e4lohhihGd/view?usp=sharing |
| Linux | narak | CVE-2021-3493 | https://drive.google.com/file/d/1OBpUaaMnZXbQWUinWp2ph-G_eRwYCRrk/view?usp=sharing |
| Windows | metasploitable3-win2k8 | CVE-2015-8249 & CVE-2015-2342 & CVE-2009-3843 & CVE-2009-4189 & CVE-2014-3120 & CVE-2016-1209 | https://drive.google.com/file/d/11NlODP-LUggcyXOGY8hH-fV8348noEDk/view?usp=sharing |
| Windows | WIN2008 | CVE-2017-0143 | https://drive.google.com/file/d/1aEJNDfHjkGADSjY8ZAB1e2tAGDVKe8Wp/view?usp=drive_link |
| Windows | WIN10-basic-target | none | https://drive.google.com/file/d/1D8f3XxdUeNbkA3Q8MwJmBjVON42qaBRH/view?usp=sharing |
| Linux | Ubuntu-base | none | https://drive.google.com/file/d/1Qwj9qHnEN6Lu-GM2Fxmzcuib0HXW0mA-/view?usp=drive_link |
| Mac | MacOS-base | none | https://drive.google.com/file/d/1HXDnXxBhyERsRNe-0Hkv3gMsJclo4zJX/view?usp=sharing	 |
| Linux | firewall | none | https://drive.google.com/file/d/1c45DjG2GJXr312Lgb81WaymIMHocusCU/view?usp=drive_link	|
| Linux | Aurora-executor-kali.ova | attacker | https://drive.google.com/file/d/1LH237s_uxqT50KrQeBPlTo7rok1m7Q7O/view?usp=drive_link |




















