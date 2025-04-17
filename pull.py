import os
import shutil
import zipfile
import tarfile
import requests
import csv
import time
from tqdm import tqdm
import argparse
from pathlib import Path
import subprocess
import gdown 
import py7zr 
import yaml
import sys

def get_unique_filename(dest_dir, file_name):
    # set differetnt names for files
    base, ext = os.path.splitext(file_name)
    counter = 1
    unique_name = file_name
    while os.path.exists(os.path.join(dest_dir, unique_name)):
        unique_name = f"{base}({counter}){ext}"
        counter += 1
    return unique_name

def download_file(url, dest_dir, csv_file):
    os.makedirs(dest_dir, exist_ok=True)
    
    try:
        file_id = url.split('/d/')[1].split('/')[0]
    except IndexError:
        print(f"[Error] 无法从 URL 提取文件 ID: {url}")
        return None

    file_name = file_id
    if os.path.exists(csv_file):
        with open(csv_file, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if row[2].strip() == url:
                    if len(row) >= 4 and row[3].strip():
                        file_name = row[3].strip()
                    break

    unique_file_name = get_unique_filename(dest_dir, file_name)
    unique_dest_path = os.path.join(dest_dir, unique_file_name)

    print(f"Downloading Google Drive file: {file_id} to {unique_dest_path}")
    try:
        gdown.download(id=file_id, output=unique_dest_path, resume=True)
        return unique_dest_path
    except Exception as e:
        print(f"Error downloading Google Drive file {url}: {e}")
        return None

def get_download_url_and_os(cve, url_table_path):
    cve = cve.lower()
    with open(url_table_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=',')
        for line in reader:
            if len(line) < 3:
                continue
            os_type_column = line[0].strip()
            cve_column = line[1].strip().lower()
            url_column = line[2].strip()
            file_name = os.path.basename(url_column)  # set URL basename as default file name
            if len(line) >= 4 and line[3].strip():
                file_name = line[3].strip()
            if cve == cve_column:
                return url_column, os_type_column, file_name
    print(f"Download URL for CVE {cve} not found!")
    return None, None, None

def handle_downloaded_file(file_path, os_type, download_dir, vm_path):
    file_name = os.path.basename(file_path)
    # extract
    if file_name.endswith('.zip') or file_name.endswith('.tar.gz') or file_name.endswith('.7z'):
        extract_and_process_files(file_path, download_dir, vm_path=vm_path)
    else:
        process_virtual_machine(file_path, vm_path)

def process_virtual_machine(file_path, vm_path):
    file_name = os.path.basename(file_path)
    if file_name.endswith('.vmdk'):
        create_vm(file_path, 'vmdk', vm_path)
    elif file_name.endswith('.iso'):
        create_vm(file_path, 'iso', vm_path)
    elif file_name.endswith('.ova') or file_name.endswith('.ovf'):
        import_ova_ovf(file_path, vm_path)

def extract_and_process_files(file_path, download_dir, vm_path=None, zip_files_to_delete=None):
    # rename
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    extract_dir = os.path.join(download_dir, base_name)
    # make sure the same name directory does not exist
    extract_dir = os.path.join(download_dir, get_unique_filename(download_dir, base_name))
    extract_archive(file_path, extract_dir)
    process_extracted_files(extract_dir, vm_path)
    if zip_files_to_delete is not None:
        zip_files_to_delete.append(file_path)

def extract_archive(file, extract_dir):
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)
    if file.endswith('.zip'):
        with zipfile.ZipFile(file, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
    elif file.endswith('.tar.gz'):
        with tarfile.open(file, 'r:gz') as tar_ref:
            tar_ref.extractall(extract_dir)
    elif file.endswith('.7z'):
        with py7zr.SevenZipFile(file, mode='r') as archive:
            archive.extractall(path=extract_dir)
    print(f"Extracted {file} to {extract_dir}")

def process_extracted_files(extract_dir, vm_path):
    # set name
    folder_name = os.path.basename(extract_dir)
    for root, _, files in os.walk(extract_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(('.vmdk', '.ova', '.ovf', '.iso')):
                base_name, ext = os.path.splitext(file)
                # rename
                if base_name != folder_name:
                    new_file_name = f"{folder_name}{ext}"
                    new_file_path = os.path.join(root, new_file_name)
                    os.rename(file_path, new_file_path)
                    print(f"Renamed {file_path} → {new_file_path}")
                    file_path = new_file_path
            # create VM
            if file_path.endswith('.vmdk'):
                create_vm(file_path, 'vmdk', vm_path)
            elif file_path.endswith('.iso'):
                create_vm(file_path, 'iso', vm_path)
            elif file_path.endswith('.ova') or file_path.endswith('.ovf'):
                import_ova_ovf(file_path, vm_path)

def create_vm(file_path, file_type, vm_path):
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    vm_name = base_name
    print(f"Creating VM from {file_path} as {vm_name}")
    
    if file_type == 'vmdk':
        create_vm_from_vmdk(file_path, vm_name, vm_path)
    elif file_type == 'iso':
        create_vm_from_iso(file_path, vm_name, vm_path)

def set_vm_resources(vm_name, vm_path):
    # makesure VM have 2GB Memory and 64MB VRAM 
    min_memory = 2048 
    min_vram = 64  

    result = subprocess.run([vm_path, "showvminfo", vm_name, "--machinereadable"], capture_output=True, text=True)
    config = result.stdout

    memory = int(next((line.split('=')[1].strip('"') for line in config.splitlines() if line.startswith("memory=")), min_memory))
    vram = int(next((line.split('=')[1].strip('"') for line in config.splitlines() if line.startswith("VRAM=")), min_vram))

    if memory < min_memory:
        subprocess.run([vm_path, "modifyvm", vm_name, "--memory", str(min_memory)])

    if vram < min_vram:
        subprocess.run([vm_path, "modifyvm", vm_name, "--vram", str(min_vram)])

def create_vm_from_vmdk(vmdk_path, vm_name, vm_path):
    vm_dir = Path(f"C:/VMs/{vm_name}")
    vm_dir.mkdir(parents=True, exist_ok=True)
    vm_disk_path = str(vm_dir / f"{vm_name}.vmdk")
    shutil.copy(vmdk_path, vm_disk_path)

    subprocess.run([vm_path, "createvm", "--name", vm_name, "--register"])
    subprocess.run([vm_path, "storagectl", vm_name, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"])
    subprocess.run([vm_path, "storageattach", vm_name, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", vm_disk_path])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic1", "nat"])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic2", "hostonly"])

    set_vm_resources(vm_name, vm_path)  

def create_vm_from_iso(iso_path, vm_name, vm_path):
    vm_dir = Path(f"C:/VMs/{vm_name}")
    vm_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run([vm_path, "createvm", "--name", vm_name, "--register"])
    subprocess.run([vm_path, "storagectl", vm_name, "--name", "IDE", "--add", "ide"])
    subprocess.run([vm_path, "storageattach", vm_name, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", iso_path])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic1", "nat"])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic2", "hostonly"])

    set_vm_resources(vm_name, vm_path) 

def import_ova_ovf(file_path, vm_path):
    vm_name = os.path.splitext(os.path.basename(file_path))[0]

    subprocess.run([vm_path, "import", file_path, "--vsys", "0", "--vmname", vm_name])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic1", "nat"])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic2", "hostonly"])

    set_vm_resources(vm_name, vm_path)  

def main():
    parser = argparse.ArgumentParser(description="Automate the download and deployment of multiple target machines.")
    parser.add_argument('-p', '--plan', help="Path to attack plan YAML file or attacker")
    parser.add_argument('-d', '--download_dir', default='downloads', help="Storage path")
    parser.add_argument('-vm', '--vm_path', default='C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe', help="VirtualBox path")
    parser.add_argument('--url_table', default='url_table.csv', help="Path to the URL table CSV file")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-r', '--repeat', action='store_true', help="Allow repeated downloads with renamed files")
    group.add_argument('-nr', '--no_repeat', action='store_true', help="Avoid repeated downloads if file or folder exists")
    args = parser.parse_args()
    download_dir = args.download_dir
    vm_path = args.vm_path
    attack_plan_path = args.plan

    targets = []
    downloaded_files = {}
    zip_files_to_delete = []

    # download attacker
    if attack_plan_path == "attacker":
        csv_path = args.url_table
        if not os.path.exists(csv_path):
            print(f"[Error] url_table.csv not found at {csv_path}")
            sys.exit(1)

        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 3 and row[0].strip() == "Linux" and row[1].strip() == "attacker":
                    download_url = row[2].strip()
                    os_type = row[0].strip()
                    custom_file_name = row[3].strip() if len(row) >= 4 else "attacker"
                    targets.append(("attacker", os_type, download_url, custom_file_name))
                    break

        if not targets:
            print("[x] No attacker record found in url_table.csv")
            sys.exit(1)

    # read yml attack plan
    elif attack_plan_path:
        print(f"Loading plan from {attack_plan_path}...")
        with open(attack_plan_path, 'r', encoding='utf-8') as f:
            plan_data = yaml.safe_load(f)
        cve_list = plan_data.get("testbed_requirement", {}).get("CVE", [])
        if not cve_list:
            cve_list = ['none']

        for cve in cve_list:
            cve = cve.strip()
            download_url, os_type, custom_file_name = get_download_url_and_os(cve, args.url_table)
            if download_url and os_type:
                targets.append((cve, os_type, download_url, custom_file_name))
            else:
                print(f"Skipping CVE {cve}, no matching entry found in table.")
    else:
        print("No plan file provided, please use -p to provide a YAML plan or 'attacker'.")
        return

    # download
    for index, (cve, os_type, download_url, custom_file_name) in enumerate(targets):
        print(f"\nProcessing target {index + 1}: CVE {cve} ({os_type})...")

        if (cve, os_type) in downloaded_files:
            print(f"Using cached file for CVE {cve} ({os_type})")
            file_path = downloaded_files[(cve, os_type)]
        else:
            base_name = os.path.splitext(custom_file_name)[0]
            potential_targets = [
                os.path.join(download_dir, f"{base_name}.ova"),
                os.path.join(download_dir, f"{base_name}.zip"),
                os.path.join(download_dir, f"{base_name}.tar.gz"),
                os.path.join(download_dir, f"{base_name}.7z"),
                os.path.join(download_dir, f"{base_name}.vmdk"),
                os.path.join(download_dir, base_name)
            ]
            print(f"Base name used: {base_name}")
            file_already_exists = any(os.path.exists(path) for path in potential_targets)
            
            if args.no_repeat and file_already_exists:
                print(f"[Skipping] {cve} already exists.")
                user_input = input("Do you want to directly start the existing VM? (yes/no): ").strip().lower()
                if user_input == "yes":
                    # start existing VM
                    existing_file = next(path for path in potential_targets if os.path.exists(path))
                    vm_name = os.path.splitext(os.path.basename(existing_file))[0]
                    print(f"Launching existing VM '{vm_name}' from {existing_file}...")

                    try:
                        subprocess.run([vm_path, "startvm", vm_name, "--type", "gui"], check=True)
                        print(f"VM '{vm_name}' started successfully.")
                    except subprocess.CalledProcessError as e:
                        print(f"Failed to start VM '{vm_name}': {e}")
                else:
                    print("Skipping as requested or you can use -r to download.")
                continue

            file_path = download_file(download_url, download_dir,args.url_table)
            if not file_path:
                print(f"Download failed for {cve} ({os_type}), skipping...")
                continue

            downloaded_files[(cve, os_type)] = file_path

        if file_path.endswith(('.zip', '.tar.gz', '.7z')):
            extract_and_process_files(file_path, download_dir, vm_path, zip_files_to_delete)
        else:
            handle_downloaded_file(file_path, os_type, download_dir, vm_path)

    for zip_file in zip_files_to_delete:
        if os.path.exists(zip_file):
            print(f"Deleting archive: {zip_file}")
            os.remove(zip_file)

    print("All VMs processed, all archives deleted.")

if __name__ == "__main__":
    main()
