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
        print(f"[Error] can not get url ID: {url}")
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
            file_name = os.path.basename(url_column)
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
    result = subprocess.run([vm_path, "list", "hostonlyifs"], capture_output=True, text=True)
    if "Name:" in result.stdout:
        first_hostonly = result.stdout.split("Name:")[1].split("\n")[0].strip()
        subprocess.run([vm_path, "modifyvm", vm_name, "--nic2", "hostonly", "--hostonlyadapter2", first_hostonly])
    else:
        print(f"[Info] No Host-Only network found, skipping NIC2 setup.")

    set_vm_resources(vm_name, vm_path)

def create_vm_from_iso(iso_path, vm_name, vm_path):
    vm_dir = Path(f"C:/VMs/{vm_name}")
    vm_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run([vm_path, "createvm", "--name", vm_name, "--register"])
    subprocess.run([vm_path, "storagectl", vm_name, "--name", "IDE", "--add", "ide"])
    subprocess.run([vm_path, "storageattach", vm_name, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", iso_path])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic1", "nat"])
    result = subprocess.run([vm_path, "list", "hostonlyifs"], capture_output=True, text=True)
    if "Name:" in result.stdout:
        first_hostonly = result.stdout.split("Name:")[1].split("\n")[0].strip()
        subprocess.run([vm_path, "modifyvm", vm_name, "--nic2", "hostonly", "--hostonlyadapter2", first_hostonly])
    else:
        print(f"[Info] No Host-Only network found, skipping NIC2 setup.")

    set_vm_resources(vm_name, vm_path)

def import_ova_ovf(file_path, vm_path):
    vm_name = os.path.splitext(os.path.basename(file_path))[0]

    subprocess.run([vm_path, "import", file_path, "--vsys", "0", "--vmname", vm_name])
    subprocess.run([vm_path, "modifyvm", vm_name, "--nic1", "nat"])
    result = subprocess.run([vm_path, "list", "hostonlyifs"], capture_output=True, text=True)
    if "Name:" in result.stdout:
        first_hostonly = result.stdout.split("Name:")[1].split("\n")[0].strip()
        subprocess.run([vm_path, "modifyvm", vm_name, "--nic2", "hostonly", "--hostonlyadapter2", first_hostonly])
    else:
        print(f"[Info] No Host-Only network found, skipping NIC2 setup.")

    set_vm_resources(vm_name, vm_path)

def main():
    parser = argparse.ArgumentParser(description="Automate the download and deployment of multiple target machines.")
    parser.add_argument('-firewall', choices=['yes', 'no'], default='no',
                        help="Whether to deploy the firewall VM first (yes/no)")
    parser.add_argument('-p', '--attack_plan', help="Path to attack plan YAML file or 'attacker'")
    parser.add_argument('-k', '--searchkey', help="Directly specify a keyword to match 'search_key' column in URL table")
    parser.add_argument('-d', '--download_dir', default='downloads', help="Storage path")
    parser.add_argument('-vm', '--vm_path', default='C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe', help="VirtualBox path")
    parser.add_argument('--url_table', default=str(Path("docs") / "url_table.csv"), help="Path to the URL table CSV file")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-r', '--repeat', action='store_true', help="Allow repeated downloads with renamed files")
    group.add_argument('-nr', '--no_repeat', action='store_true', help="Avoid repeated downloads if file or folder exists")
    args = parser.parse_args()

    download_dir = args.download_dir
    vm_path = args.vm_path
    url_table_path = args.url_table
    downloaded_files = {}
    zip_files_to_delete = []
    if not args.repeat and not args.no_repeat:
        args.no_repeat = True
    # Firewall VM handling (highest priority)
    if args.firewall == 'yes':
        print("\nProcessing firewall VM first...")
        with open(url_table_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 3 and row[1].strip().lower() == 'firewall':
                    os_type = row[0].strip()
                    download_url = row[2].strip()
                    file_name = row[3].strip() if len(row) >= 4 and row[3].strip() else 'firewall'
                    base_name = os.path.splitext(file_name)[0]
                    potential = [
                        os.path.join(download_dir, f"{base_name}.ova"),
                        os.path.join(download_dir, f"{base_name}.zip"),
                        os.path.join(download_dir, f"{base_name}.tar.gz"),
                        os.path.join(download_dir, f"{base_name}.7z"),
                        os.path.join(download_dir, f"{base_name}.vmdk"),
                        os.path.join(download_dir, base_name)
                    ]
                    exists = any(os.path.exists(p) for p in potential)
                    if exists:
                        print(f"[Skipping] firewall VM already exists.")
                        choice = input("Do you want to start the existing firewall VM? (yes/no): ").strip().lower()
                        if choice == 'yes':
                            existing = next(p for p in potential if os.path.exists(p))
                            vm_name = os.path.splitext(os.path.basename(existing))[0]
                            subprocess.run([vm_path, 'startvm', vm_name, '--type', 'gui'])
                        continue

                    file_path = download_file(download_url, download_dir, url_table_path)
                    if not file_path:
                        print("Firewall download failed, skipping firewall VM.")
                        continue
                    downloaded_files[('firewall', os_type)] = file_path
                    if file_path.endswith(('.zip', '.tar.gz', '.7z')):
                        extract_and_process_files(file_path, download_dir, vm_path, zip_files_to_delete)
                    else:
                        handle_downloaded_file(file_path, os_type, download_dir, vm_path)
                    break

    targets = []

    # Keyword mode
    if args.searchkey:
        keys = [k.strip().lower() for k in args.searchkey.split(',') if k.strip()]
        print(f"\n[Keyword Mode] Searching for keywords: {keys} in URL table...")

        found = False
        with open(url_table_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 3:
                    continue
                os_type = row[1].strip()
                raw_keys = row[3].strip() if len(row) >= 4 and row[3].strip() else ""
                row_keys = [k.strip().lower() for k in raw_keys.split(',') if k.strip()]
                download_url = row[4].strip()
                file_name = row[5].strip() if len(row) >= 6 and row[5].strip() else "downloaded_file"

                # if keyword match row one of search_key
                if any(key in row_keys for key in keys):
                    matched_key = next((k for k in keys if k in row_keys), keys[0])
                    targets.append((matched_key, os_type, download_url, file_name))
                    found = True

        if not found:
            print(f"No match found for any of the keywords: {keys} in URL table.")
            return


    # Plan mode
    elif args.attack_plan:
        print(f"\nLoading plan from {args.attack_plan}...")
        with open(args.attack_plan, 'r', encoding='utf-8') as f:
            plan_data = yaml.safe_load(f)
        testbed = plan_data.get('testbed_requirement', {})

        # read URL table
        with open(url_table_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            url_table = [row for row in reader if len(row) >= 6]

        # 1. download attacker（search_key == attacker）
        attacker_row = next((row for row in url_table if row[3].strip().lower() == 'attacker'), None)
        if attacker_row:
            os_type = attacker_row[1].strip()
            download_url = attacker_row[4].strip()
            file_name = attacker_row[5].strip()
            base_name = os.path.splitext(file_name)[0]
            potential = [
                os.path.join(download_dir, f"{base_name}.ova"),
                os.path.join(download_dir, base_name)
            ]
            exists = any(os.path.exists(p) for p in potential)

            if args.no_repeat and exists:
                print(f"[Skipping] attacker VM already exists.")
                user_input = input("Do you want to directly start the existing attacker VM? (yes/no): ").strip().lower()
                if user_input == "yes":
                    existing_file = next(path for path in potential if os.path.exists(path))
                    vm_name = os.path.splitext(os.path.basename(existing_file))[0]
                    print(f"Launching attacker VM '{vm_name}'...")
                    subprocess.run([vm_path, "startvm", vm_name, "--type", "gui"])
            else:
                print(f"\n[Attacker] Downloading and processing attacker VM...")
                file_path = download_file(download_url, download_dir, url_table_path)
                if not file_path:
                    print("[Error] Failed to download attacker VM.")
                elif file_path.endswith(('.zip', '.tar.gz', '.7z')):
                    extract_and_process_files(file_path, download_dir, vm_path, zip_files_to_delete)
                else:
                    handle_downloaded_file(file_path, os_type, download_dir, vm_path)
        else:
            print("[Warning] No 'attacker' entry found in URL table.")

        # 2. search YAML host（get host_id）
        for host_id in testbed:
            matched = False
            for row in url_table:
                table_host_id = row[0].strip()
                if host_id.strip().lower() == table_host_id.lower():
                    os_type = row[1].strip()
                    search_key = row[3].strip()
                    url = row[4].strip()
                    file_name = row[5].strip()
                    base_name = os.path.splitext(file_name)[0]
                    potential = [
                        os.path.join(download_dir, f"{base_name}.ova"),
                        os.path.join(download_dir, f"{base_name}.zip"),
                        os.path.join(download_dir, f"{base_name}.tar.gz"),
                        os.path.join(download_dir, f"{base_name}.7z"),
                        os.path.join(download_dir, f"{base_name}.vmdk"),
                        os.path.join(download_dir, base_name)
                    ]
                    exists = any(os.path.exists(p) for p in potential)

                    if args.no_repeat and exists:
                        print(f"[Skipping] {host_id} already exists.")
                        user_input = input(f"Do you want to directly start the existing VM for '{host_id}'? (yes/no): ").strip().lower()
                        if user_input == "yes":
                            existing_file = next(path for path in potential if os.path.exists(path))
                            vm_name = os.path.splitext(os.path.basename(existing_file))[0]
                            print(f"Launching existing VM '{vm_name}'...")
                            try:
                                subprocess.run([vm_path, "startvm", vm_name, "--type", "gui"])
                                print(f"VM '{vm_name}' started successfully.")
                            except subprocess.CalledProcessError as e:
                                print(f"Failed to start VM '{vm_name}': {e}")
                        else:
                            print("Skipping as requested or you can use -r to force download.")
                        matched = True
                        break

                    file_path = download_file(url, download_dir, url_table_path)
                    if not file_path:
                        print(f"[Error] Failed to download VM for host {host_id}.")
                        break
                    downloaded_files[(host_id, os_type)] = file_path
                    if file_path.endswith(('.zip', '.tar.gz', '.7z')):
                        extract_and_process_files(file_path, download_dir, vm_path, zip_files_to_delete)
                    else:
                        handle_downloaded_file(file_path, os_type, download_dir, vm_path)
                    matched = True
                    break
            if not matched:
                print(f"[Warning] No match found for host '{host_id}' in URL table.")
                print("Available host_ids in URL table:")
                for row in url_table:
                    print(f"  - {row[0].strip()}")


    # Process targets
    for idx, (cve, os_type, download_url, custom_file_name) in enumerate(targets, 1):
        print(f"\nProcessing target {idx}: {cve} ({os_type})...")
        base_name = os.path.splitext(custom_file_name)[0]
        potential = [
            os.path.join(download_dir, f"{base_name}.ova"),
            os.path.join(download_dir, f"{base_name}.zip"),
            os.path.join(download_dir, f"{base_name}.tar.gz"),
            os.path.join(download_dir, f"{base_name}.7z"),
            os.path.join(download_dir, f"{base_name}.vmdk"),
            os.path.join(download_dir, base_name)
        ]
        exists = any(os.path.exists(p) for p in potential)
        if args.no_repeat and exists:
            print(f"[Skipping] {cve} already exists.")
            user_input = input("Do you want to directly start the existing VM? (yes/no): ").strip().lower()
            if user_input == "yes":
                existing_file = next(path for path in potential if os.path.exists(path))
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

        file_path = download_file(download_url, download_dir, url_table_path)
        if not file_path:
            print(f"Download failed for {cve}, skipping.")
            continue
        downloaded_files[(cve, os_type)] = file_path
        if file_path.endswith(('.zip', '.tar.gz', '.7z')):
            extract_and_process_files(file_path, download_dir, vm_path, zip_files_to_delete)
        else:
            handle_downloaded_file(file_path, os_type, download_dir, vm_path)

    # Cleanup archives
    for z in zip_files_to_delete:
        if os.path.exists(z):
            print(f"Deleting archive: {z}")
            os.remove(z)

    print("All VMs processed, all archives deleted.")


if __name__ == '__main__':
    main()
