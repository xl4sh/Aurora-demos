# Pull and deploy the attack range: 
After successfully generating the yml file of the attack chain, you can use pull.py to automatically read the files within it to automatically pull and deploy the virtual machine range. 

Note that automatic deployment is applicable to VirtualBox. Of course, if you are using Vmware, you can also manually deploy it yourself based on the downloaded files.



```bash
# Prohibited repeated deployment
python pull.py -p #yml file path -d #storage path -vm #VBoxManage.exe path -nr
# Allow for repeated deployment
python pull.py -p #yml file path -d #storage path -vm #VBoxManage.exe path -r
```
# Generation of attack scripts: 


```bash
```
# Execution of attack script: 


```bash
```

