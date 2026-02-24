#!/usr/bin/env bash
# Clear the screen
clear
# Script to image devices with linux Distro
# v2022.01.01
# Updated January 2026
# GPL 3.0
#
# Script developed to assist in Forensic collection and reports
# With this script you will be able to achieve some goals:
# 1) Get valuable information about the host
# 2) Securely save image in encrypted disks
# 3) Perform forensic imaging in various formats
# 4) Receive a device collection report
#
# This script has a few assumptions:
# 1) Use the custodian's computer as the imaging platform
# 2) Use this script for device collection
# 3) Have intermediate knowledge in Linux
# 4) Have target and backup disks, preferably preformatted
# 5) Use VeraCrypt encryption

### Colors ##
ESC=$(printf '\033') RESET="${ESC}[0m" BLACK="${ESC}[30m" RED="${ESC}[31m"
GREEN="${ESC}[32m" YELLOW="${ESC}[33m" BLUE="${ESC}[34m" MAGENTA="${ESC}[35m"
CYAN="${ESC}[36m" WHITE="${ESC}[37m" DEFAULT="${ESC}[39m"

### Color Functions ##
greenprint() { printf "${GREEN}%s${RESET}\n" "$1"; }
blueprint() { printf "${BLUE}%s${RESET}\n" "$1"; }
redprint() { printf "${RED}%s${RESET}\n" "$1"; }
yellowprint() { printf "${YELLOW}%s${RESET}\n" "$1"; }
magentaprint() { printf "${MAGENTA}%s${RESET}\n" "$1"; }
cyanprint() { printf "${CYAN}%s${RESET}\n" "$1"; }
fn_goodafternoon() { echo; echo "Good afternoon."; }
fn_goodmorning() { echo; echo "Good morning."; }
fn_bye() { echo "Bye bye."; exit 0; }
fn_fail() { echo "Wrong option."; exit 1; }

forensic_user=""
forensic_home=""
forensic_desktop=""
output_report=""
output_csv=""
output_json=""
output_tsv=""
audit_format=csv

fn_set_forensic_paths() {
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        forensic_user="$SUDO_USER"
    elif [ -n "$PKEXEC_UID" ]; then
        forensic_user="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
    else
        forensic_user="$(logname 2>/dev/null || true)"
    fi

    if [ -z "$forensic_user" ] || [ "$forensic_user" = "root" ]; then
        forensic_user="$USER"
    fi

    forensic_home="$(getent passwd "$forensic_user" | cut -d: -f6)"
    if [ -z "$forensic_home" ]; then
        forensic_home="$HOME"
    fi

    forensic_desktop="$forensic_home/Desktop"
    if [ ! -d "$forensic_desktop" ]; then
        forensic_desktop="$forensic_home"
    fi

    output_report="$forensic_desktop/forensic_report.log"
    output_csv="$forensic_desktop/forensic_report.csv"
    output_json="$forensic_desktop/forensic_report.json"
    output_tsv="$forensic_desktop/forensic_report.tsv"
}

fn_init_audit_files() {
    mkdir -p "$(dirname "$output_report")"
    : > "$output_report"
    : > "$output_csv"
    : > "$output_json"
    : > "$output_tsv"
    echo "timestamp,section,key,value" >> "$output_csv"
    echo -e "timestamp	section	key	value" >> "$output_tsv"
    echo "[" >> "$output_json"
}

fn_close_audit_json() {
    if [ -f "$output_json" ] && { [ "$audit_format" = "json" ] || [ "$audit_format" = "all" ]; }; then
        sed -i '$ s/,$//' "$output_json"
        echo "]" >> "$output_json"
    else
        rm -f "$output_json"
    fi
}

fn_audit_write() {
    section="$1"
    key="$2"
    value="$3"
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    csv_value=$(printf '%s' "$value" | sed 's/"/""/g')
    json_value=$(printf '%s' "$value" | sed 's/"/\\"/g')
    printf '%s [%s] %s=%s\n' "$ts" "$section" "$key" "$value" | tee -a "$output_report" >/dev/null
    if [ "$audit_format" = "csv" ] || [ "$audit_format" = "all" ]; then
        printf '%s,%s,%s,"%s"\n' "$ts" "$section" "$key" "$csv_value" >> "$output_csv"
    fi
    if [ "$audit_format" = "tsv" ] || [ "$audit_format" = "all" ]; then
        printf '%s\t%s\t%s\t%s\n' "$ts" "$section" "$key" "$value" >> "$output_tsv"
    fi
    if [ "$audit_format" = "json" ] || [ "$audit_format" = "all" ]; then
        printf '{"timestamp":"%s","section":"%s","key":"%s","value":"%s"},\n' "$ts" "$section" "$key" "$json_value" >> "$output_json"
    fi
}


fn_calculate_blocksize() {
    lba_value="$1"
    if ! [[ "$lba_value" =~ ^[0-9]+$ ]]; then
        echo 512
        return
    fi

    if (((lba_value %64) == 0)); then
        echo 32768
    elif (((lba_value %32) == 0)); then
        echo 16384
    elif (((lba_value %16) == 0)); then
        echo 8192
    elif (((lba_value %8) == 0)); then
        echo 4096
    elif (((lba_value %4) == 0)); then
        echo 2048
    elif (((lba_value %2) == 0)); then
        echo 1024
    else
        echo 512
    fi
}

fn_choose_audit_format() {
    echo
    echo "Choose audit output mode:"
    echo "1) CSV"
    echo "2) JSON"
    echo "3) TSV"
    echo "4) ALL (default)"
    echo -n "Option: "
    read -r audit_opt
    case "$audit_opt" in
        1) audit_format="csv" ;;
        2) audit_format="json" ;;
        3) audit_format="tsv" ;;
        *) audit_format="all" ;;
    esac
    fn_audit_write "audit" "selected_format" "$audit_format"
}

fn_record_time_seal() {
    seal_phase="$1"
    utc_now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    local_now="$(date +"%Y-%m-%dT%H:%M:%S%z")"
    tz_local="$(date +"%Z")"
    clock_source="$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo unknown)"
    ntp_sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
    ntp_service="$(timedatectl show -p NTP --value 2>/dev/null || echo unknown)"
    ntp_offset="$(chronyc tracking 2>/dev/null | awk -F':' '/Last offset/ {gsub(/^ +/,"",$2); print $2}' || true)"
    [ -z "$ntp_offset" ] && ntp_offset="unknown"
    fn_audit_write "time_seal" "phase" "$seal_phase"
    fn_audit_write "time_seal" "utc" "$utc_now"
    fn_audit_write "time_seal" "local" "$local_now"
    fn_audit_write "time_seal" "timezone" "$tz_local"
    fn_audit_write "time_seal" "clock_source" "$clock_source"
    fn_audit_write "time_seal" "ntp_sync" "$ntp_sync"
    fn_audit_write "time_seal" "ntp_service" "$ntp_service"
    fn_audit_write "time_seal" "ntp_offset" "$ntp_offset"
}

fn_collect_disk_telemetry() {
    dev="$1"
    role="$2"
    fn_audit_write "$role.telemetry" "lsblk" "$(lsblk -d -o NAME,MODEL,SERIAL,SIZE,ROTA,TYPE,TRAN /dev/$dev 2>/dev/null | tr '
' ';')"
    smartctl -x "/dev/$dev" >> "$output_report" 2>/dev/null || true
    fn_audit_write "$role.telemetry" "smartctl" "captured"
    if [[ "$dev" == nvme* ]]; then
        nvme id-ctrl "/dev/$dev" >> "$output_report" 2>/dev/null || true
        nvme smart-log "/dev/$dev" >> "$output_report" 2>/dev/null || true
        fn_audit_write "$role.telemetry" "nvme_cli" "captured"
    fi
}

fn_generate_manifest_hashes() {
    target_path="$1"
    manifest_file="$forensic_desktop/forensic_manifest_$(date -u +%Y%m%dT%H%M%SZ).txt"
    [ -f "$target_path" ] || return 0
    md5sum "$target_path" | tee -a "$manifest_file" >> "$output_report"
    if command -v b3sum >/dev/null 2>&1; then
        b3sum "$target_path" | tee -a "$manifest_file" >> "$output_report"
        fn_audit_write "hash" "secondary" "b3sum"
    else
        sha256sum "$target_path" | tee -a "$manifest_file" >> "$output_report"
        fn_audit_write "hash" "secondary" "sha256sum"
    fi
    fn_audit_write "hash" "manifest" "$manifest_file"
}

fn_hash_onthefly_clone() {
    src_dev="$1"
    dst_file="$2"
    [ -b "/dev/$src_dev" ] || return 1
    dd if="/dev/$src_dev" bs=${blocksize:-4096} status=progress | tee "$dst_file" | md5sum | tee -a "$output_report" >/dev/null
    fn_generate_manifest_hashes "$dst_file"
}

fn_sign_structured_outputs() {
    cert_dir="$forensic_desktop/.forensic_sign"
    key_file="$cert_dir/forensic_local.key"
    crt_file="$cert_dir/forensic_local.crt"
    mkdir -p "$cert_dir"

    if [ ! -f "$key_file" ] || [ ! -f "$crt_file" ]; then
        openssl req -x509 -newkey rsa:3072 -keyout "$key_file" -out "$crt_file" -days 3650 -nodes \
            -subj "/CN=Forensic Local Signing/O=DFIR Local/C=BR" >/dev/null 2>&1 || true
    fi

    if [ -f "$output_csv" ]; then
        openssl dgst -sha256 -sign "$key_file" -out "$output_csv.sig" "$output_csv" 2>/dev/null || true
        fn_audit_write "signature" "csv" "$output_csv.sig"
    fi
    if [ -f "$output_json" ]; then
        openssl dgst -sha256 -sign "$key_file" -out "$output_json.sig" "$output_json" 2>/dev/null || true
        fn_audit_write "signature" "json" "$output_json.sig"
    fi
    fn_audit_write "signature" "certificate" "$crt_file"
}

fn_record_boot_chain() {
    fn_audit_write "boot_chain" "kernel" "$(uname -a)"
    fn_audit_write "boot_chain" "cmdline" "$(cat /proc/cmdline 2>/dev/null)"
    if [ -d /sys/firmware/efi ]; then
        fn_audit_write "boot_chain" "firmware" "UEFI"
        fn_audit_write "boot_chain" "secure_boot" "$(mokutil --sb-state 2>/dev/null | head -n1 || echo unknown)"
    else
        fn_audit_write "boot_chain" "firmware" "Legacy/BIOS"
    fi
}

fn_acquisition_menu() {
    echo "1) AFF (affcopy)"
    echo "2) EnCase E01 (ewfacquire)"
    echo "3) DD (dc3dd)"
    echo "4) Physical damaged (ddrescue) [best for badblocks]"
    echo "5) RAW (ftkimager) [often fastest raw path]"
    echo -n "Option: "
    read -r acq_opt
    case "$acq_opt" in
        1) fn_acquire_aff ;;
        2) fn_acquire_encase ;;
        3) fn_acquire_dd ;;
        4) fn_acquire_img ;;
        5) fn_acquire_raw ;;
        *) fn_fail ;;
    esac
}

fn_cloud_collect_m365() {
    out_dir="$forensic_desktop/cloud/m365_$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out_dir"
    fn_audit_write "cloud" "provider" "microsoft365"
    fn_audit_write "cloud" "output_dir" "$out_dir"

    if command -v m365 >/dev/null 2>&1; then
        m365 status > "$out_dir/m365_status.json" 2>>"$output_report" || true
        m365 aad user list --output json > "$out_dir/aad_users.json" 2>>"$output_report" || true
        m365 outlook message list --folder Inbox --output json > "$out_dir/outlook_inbox.json" 2>>"$output_report" || true
        fn_audit_write "cloud" "collector" "m365_cli"
    elif command -v rclone >/dev/null 2>&1; then
        rclone lsjson m365: > "$out_dir/rclone_lsjson_root.json" 2>>"$output_report" || true
        fn_audit_write "cloud" "collector" "rclone_m365_remote"
    else
        echo "No M365 collector found (m365 or rclone)." | tee -a "$output_report"
        fn_audit_write "cloud" "collector" "missing"
    fi

    find "$out_dir" -type f -print0 | while IFS= read -r -d '' f; do
        fn_generate_manifest_hashes "$f"
    done
}

fn_cloud_collect_google() {
    out_dir="$forensic_desktop/cloud/google_$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out_dir"
    fn_audit_write "cloud" "provider" "google_workspace"
    fn_audit_write "cloud" "output_dir" "$out_dir"

    if command -v gam >/dev/null 2>&1; then
        gam print users fields primaryEmail,suspended,orgUnitPath > "$out_dir/gam_users.csv" 2>>"$output_report" || true
        fn_audit_write "cloud" "collector" "gam"
    elif command -v rclone >/dev/null 2>&1; then
        rclone lsjson gdrive: > "$out_dir/rclone_lsjson_root.json" 2>>"$output_report" || true
        fn_audit_write "cloud" "collector" "rclone_gdrive_remote"
    else
        echo "No Google collector found (gam or rclone)." | tee -a "$output_report"
        fn_audit_write "cloud" "collector" "missing"
    fi

    find "$out_dir" -type f -print0 | while IFS= read -r -d '' f; do
        fn_generate_manifest_hashes "$f"
    done
}

fn_cloud_module(){
    echo "Cloud collection module (corporate DFIR)"
    echo "1) Microsoft 365 collection"
    echo "2) Google Workspace/Gmail collection"
    echo -n "Option: "
    read -r cloud_opt
    case "$cloud_opt" in
      1) fn_cloud_collect_m365 ;;
      2) fn_cloud_collect_google ;;
      *) fn_fail ;;
    esac
    fn_audit_write "cloud" "mode" "online_collection"
}

fn_acquire_encase(){
    out="$tgt_mnt/$evid_barcode/$evid_barcode.E01"
    ewfacquire "/dev/$evid_dev" -u -t "$tgt_mnt/$evid_barcode/$evid_barcode" >> "$output_report" 2>&1 || true
    fn_generate_manifest_hashes "$out"
    fn_audit_write "acquisition" "encase_e01" "$out"
}

fn_acquire_dd(){
    out="$tgt_mnt/$evid_barcode/$evid_barcode.dd"
    dc3dd if="/dev/$evid_dev" of="$out" hash=md5 hashlog="$out.md5" log="$output_report" >> "$output_report" 2>&1 || true
    fn_generate_manifest_hashes "$out"
    fn_audit_write "acquisition" "dd_output" "$out"
}

fn_memory_live_module(){
    echo -n "Memory output directory: "
    read -r mem_out
    [ -z "$mem_out" ] && mem_out="$forensic_desktop"
    mem_file="$mem_out/memory_$(date -u +%Y%m%dT%H%M%SZ).lime"
    if command -v avml >/dev/null 2>&1; then
        avml "$mem_file" >> "$output_report" 2>&1 || true
    elif command -v limeutil >/dev/null 2>&1; then
        limeutil "$mem_file" >> "$output_report" 2>&1 || true
    else
        echo "No live memory collector found (avml/limeutil)." | tee -a "$output_report"
    fi
    fn_generate_manifest_hashes "$mem_file"
    fn_audit_write "memory" "output" "$mem_file"
}

fn_timeline_module(){
    echo -n "Evidence input path for timeline: "
    read -r timeline_input
    echo -n "Timeline output directory: "
    read -r timeline_out
    [ -z "$timeline_out" ] && timeline_out="$forensic_desktop"
    case_dir="$timeline_out/plaso_case"
    mkdir -p "$case_dir"
    log2timeline.py "$case_dir/timeline.plaso" "$timeline_input" >> "$output_report" 2>&1 || true
    psort.py -o l2tcsv "$case_dir/timeline.plaso" > "$case_dir/timeline.csv" 2>>"$output_report" || true
    fn_audit_write "timeline" "plaso" "$case_dir/timeline.plaso"
    fn_audit_write "timeline" "csv" "$case_dir/timeline.csv"
    echo "Timesketch import: upload $case_dir/timeline.plaso" | tee -a "$output_report"
}

fn_mobile_collect_android() {
    mobile_out="$1"
    and_dir="$mobile_out/android_$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$and_dir"

    if command -v adb >/dev/null 2>&1; then
        adb devices -l > "$and_dir/adb_devices.txt" 2>>"$output_report" || true
        adb shell getprop > "$and_dir/getprop.txt" 2>>"$output_report" || true
        adb bugreport "$and_dir/bugreport.zip" >> "$output_report" 2>&1 || true
        fn_audit_write "mobile.android" "collector" "adb"
    fi

    if [ -d /opt/ALEAPP ]; then
        python3 /opt/ALEAPP/aleapp.py -i "$and_dir" -o "$and_dir/aleapp_report" >> "$output_report" 2>&1 || true
        fn_audit_write "mobile.android" "collector" "aleapp"
    fi

    find "$and_dir" -type f -print0 | while IFS= read -r -d '' f; do
        fn_generate_manifest_hashes "$f"
    done
}

fn_mobile_collect_ios() {
    mobile_out="$1"
    ios_dir="$mobile_out/ios_$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$ios_dir"

    if command -v ideviceinfo >/dev/null 2>&1; then
        ideviceinfo > "$ios_dir/ideviceinfo.txt" 2>>"$output_report" || true
    fi

    if command -v idevicebackup2 >/dev/null 2>&1; then
        idevicebackup2 backup "$ios_dir/itunes_backup" >> "$output_report" 2>&1 || true
        fn_audit_write "mobile.ios" "collector" "idevicebackup2"
    fi

    if [ -d /opt/iLEAPP ]; then
        python3 /opt/iLEAPP/ileapp.py -i "$ios_dir/itunes_backup" -o "$ios_dir/ileapp_report" >> "$output_report" 2>&1 || true
        fn_audit_write "mobile.ios" "collector" "ileapp"
    fi

    find "$ios_dir" -type f -print0 | while IFS= read -r -d '' f; do
        fn_generate_manifest_hashes "$f"
    done
}

fn_mobile_module(){
    echo -n "Mobile evidence output dir: "
    read -r mobile_out
    [ -z "$mobile_out" ] && mobile_out="$forensic_desktop/mobile"
    mkdir -p "$mobile_out"

    echo "1) Android collection (ADB + ALEAPP if available)"
    echo "2) iOS collection (iTunes backup + iLEAPP if available)"
    echo "3) Full mobile (Android + iOS)"
    echo -n "Option: "
    read -r mob_opt
    case "$mob_opt" in
      1) fn_mobile_collect_android "$mobile_out" ;;
      2) fn_mobile_collect_ios "$mobile_out" ;;
      3) fn_mobile_collect_android "$mobile_out"; fn_mobile_collect_ios "$mobile_out" ;;
      *) fn_fail ;;
    esac
}

forensic_framework() {
    echo -ne "
$(greenprint 'REPORT ACQUISITION')
$(greenprint '1)') READ ME FIRST
$(yellowprint '2)') START ACQUISITION THE INFORMATION
$(blueprint '3)') GENERATE REPORT
$(magentaprint '4)') CANCEL CURRENT ACTION
$(cyanprint '5)') ACQUISITION MODULES
$(cyanprint '6)') MEMORY LIVE MODULE
$(cyanprint '7)') TIMELINE MODULE
$(cyanprint '8)') MOBILE MODULE
$(cyanprint '9)') CLOUD MODULE
$(redprint '0)') Exit
Choose an option:  "
    read -r ans
    case $ans in
    1)
        fn_goodmorning
        function_readme
        forensic_framework
        ;;
    2)
        fn_init_audit_files
        fn_record_time_seal "start"
        fn_record_boot_chain
        fn_choose_audit_format
        fn_getinfo
        fn_get_diskinfo
        fn_output_getinfo
        fn_report
        fn_report_evidence
        fn_collect_disk_telemetry "$evid_dev" "evidence"
        fn_report_target
        fn_collect_disk_telemetry "$tgt_dev" "target"
        fn_report_backup
        fn_collect_disk_telemetry "$bkp_dev" "backup"
        fn_report_working
        fn_report_connected-devices
        fn_report_mounted-filesystems
        fn_report_available-freespace
        fn_encrypt
        fn_summary
        fn_record_time_seal "end"
        fn_close_audit_json
        fn_sign_structured_outputs
        forensic_framework
        ;;
    3)
        fn_get_diskinfo
        forensic_framework
        ;;
    4)
        echo "Operation canceled by user."
        fn_audit_write "menu" "cancel" "true"
        forensic_framework
        ;;
    5)
        fn_acquisition_menu
        forensic_framework
        ;;
    6)
        fn_memory_live_module
        forensic_framework
        ;;
    7)
        fn_timeline_module
        forensic_framework
        ;;
    8)
        fn_mobile_module
        forensic_framework
        ;;
    9)
        fn_cloud_module
        forensic_framework
        ;;
    0)
        fn_bye
        ;;
    *)
        fn_fail
        ;;
    esac
}

fn_report() {
curr_date=`date +"%A, %B %d, %Y"`
curr_time=`date +"%H:%M"`
timezone_host=`date +"%:::z %Z"`
host_type=`dmidecode -t 3 | grep Type | awk '{print $2}'`
host_manufacturer=`dmidecode -s system-manufacturer`
host_product_name=`dmidecode -s baseboard-product-name`
host_version=`dmidecode -s system-version`
host_serial_number=`dmidecode -s system-serial-number`
host_system_family=`dmidecode -s system-family`
host_bios_vendor=`dmidecode -s bios-vendor`
bios_date=`date +"%A, %B %d, %Y"`
bios_date_formated=`date +"%4Y-%m-%d"`
bios_time=`date +"%H:%M"`
host_timeZone=`date +"%:::z %Z"`
datetime_host=`date +"%4Y-%m-%d %H:%M %:::z %Z"`
datetime_utc0=`date -u +"%4Y-%m-%d %H:%M %:::z %Z"`
#host information
echo "******************************************"
echo "*           Host Information             *"
echo "******************************************"
echo
echo $(blueprint "Host Type:") $host_type 
echo $(blueprint "Host Manufacturer:") $host_manufacturer
echo $(blueprint "Host Product Name:") $host_product_name 
echo $(blueprint "Host Tag:") $host_tag
echo $(blueprint "Host Version:") $host_version
echo $(blueprint "Host Serial Number:") $host_serial_number
echo $(blueprint "BIOS Date:") $bios_date
echo $(blueprint "BIOS Time:") $bios_time 
echo
fn_audit_write "host" "type" "$host_type"
fn_audit_write "host" "manufacturer" "$host_manufacturer"
fn_audit_write "host" "product_name" "$host_product_name"
fn_audit_write "host" "tag" "$host_tag"
fn_audit_write "host" "version" "$host_version"
fn_audit_write "host" "serial_number" "$host_serial_number"
fn_audit_write "host" "bios_date" "$bios_date"
fn_audit_write "host" "bios_time" "$bios_time"
}

fn_report_evidence() {
evid_dev_model=`/bin/udevadm info --name=/dev/$evid_dev | egrep ID_MODEL | awk  -F'[=,]' '{print $2}' | sed -n 1p`
evid_dev_vendor=`/bin/udevadm info --name=/dev/$evid_dev | egrep ID_VENDOR | awk  -F'[=,]' '{print $2}' | sed -n 1p`
evid_dev_serial=`/bin/udevadm info --name=/dev/$evid_dev | egrep ID_SERIAL_SHORT | awk  -F'[=,]' '{print $2}'`
evid_dev_firmware=`hdparm -I /dev/$evid_dev 2>/dev/null | grep -i 'Firmware Revision' | awk '{print $3" "$4" "$5" "$6}'`
LBASectors=`hdparm -g /dev/$evid_dev | awk -F'[=,]' '{print $4}'`
evid_transport=`/bin/udevadm info --name=/dev/$evid_dev | egrep ID_BUS | awk  -F'[=,]' '{print $2}'`
evid_sectors=`echo $LBASectors | awk '{print $1}'`
evid_bytes=`fdisk -l -u /dev/$evid_dev | grep $evid_dev | grep bytes | awk '{print $5}'`
evid_size=`fdisk -l -u /dev/$evid_dev | grep Disk | grep $evid_dev | awk '{print $3$4}'`
evid_part_count=`fdisk -l -u /dev/$evid_dev | grep $evid_dev | grep -v Disk | wc -l`
evid_part1_field2=`fdisk -l -u /dev/$evid_dev | grep -A1 Device | grep $evid_dev'1' | awk '{print $2}'`
evid_part1_field3=`fdisk -l -u /dev/$evid_dev | grep -A1 Device | grep $evid_dev'1' | awk '{print $3}'`
evid_part2_field2=`fdisk -l -u /dev/$evid_dev | grep -A2 Device | grep $evid_dev'2' | awk '{print $2}'`
evid_part2_field3=`fdisk -l -u /dev/$evid_dev | grep -A2 Device | grep $evid_dev'2' | awk '{print $3}'`
trim_status=`sudo systemctl status fstrim | grep Active | awk '{print $2}'`
#evidence information
echo "******************************************"
echo "*         Evidence Information           *"
echo "******************************************"
echo
echo $(blueprint "Evidence mount point:") "/dev/$evid_dev" 
echo $(blueprint "Evidence device vendor:") "$evid_dev_vendor" 
echo $(blueprint "Evidence device model:") "$evid_dev_model" 
echo $(blueprint "Evidence device serial:") "$evid_dev_serial" 
echo $(blueprint "Evidence device firmware:") "$evid_dev_firmware" 
echo $(blueprint "Evidence transport type:") "$evid_transport"
echo $(blueprint "Evidence trim status:") "$trim_status"
echo $(blueprint "Evidence sectors:") "$evid_sectors"
echo $(blueprint "Evidence bytes:") "$evid_bytes"
echo $(blueprint "Evidence size:") "$evid_size" 
blocksize=$(fn_calculate_blocksize "$LBASectors")
echo $(blueprint "Evidence blocksize:") $blocksize | tee -a $output_report
echo
fn_audit_write "evidence" "mount_point" "/dev/$evid_dev"
fn_audit_write "evidence" "vendor" "$evid_dev_vendor"
fn_audit_write "evidence" "model" "$evid_dev_model"
fn_audit_write "evidence" "serial" "$evid_dev_serial"
fn_audit_write "evidence" "firmware" "$evid_dev_firmware"
fn_audit_write "evidence" "transport" "$evid_transport"
fn_audit_write "evidence" "trim_status" "$trim_status"
fn_audit_write "evidence" "sectors" "$evid_sectors"
fn_audit_write "evidence" "bytes" "$evid_bytes"
fn_audit_write "evidence" "size" "$evid_size"
fn_audit_write "evidence" "blocksize" "$blocksize"
}

fn_report_target() {
tgt_dev_model=`/bin/udevadm info --name=/dev/$tgt_dev | egrep ID_MODEL | awk  -F'[=,]' '{print $2}' | sed -n 1p`
tgt_dev_vendor=`/bin/udevadm info --name=/dev/$tgt_dev | egrep ID_VENDOR | awk  -F'[=,]' '{print $2}' | sed -n 1p`
tgt_dev_serial=`/bin/udevadm info --name=/dev/$tgt_dev | egrep ID_SERIAL_SHORT | awk  -F'[=,]' '{print $2}'`
tgt_dev_firmware=`hdparm -I /dev/$tgt_dev 2>/dev/null | grep -i 'Firmware Revision' | awk '{print $3" "$4" "$5" "$6}'`
LBASectors=`hdparm -g /dev/$tgt_dev | awk -F'[=,]' '{print $4}'`
tgt_transport=`/bin/udevadm info --name=/dev/$tgt_dev | egrep ID_BUS | awk  -F'[=,]' '{print $2}'`
tgt_sectors=`echo $LBASectors | awk '{print $1}'`
tgt_bytes=`fdisk -l -u /dev/$tgt_dev | grep $tgt_dev | grep bytes | awk '{print $5}'`
tgt_size=`fdisk -l -u /dev/$tgt_dev | grep Disk | grep $tgt_dev | awk '{print $3$4}'`
tgt_part_count=`fdisk -l -u /dev/$tgt_dev | grep $tgt_dev | grep -v Disk | wc -l`
tgt_part1_field2=`fdisk -l -u /dev/$tgt_dev | grep -A1 Device | grep $tgt_dev'1' | awk '{print $2}'`
tgt_part1_field3=`fdisk -l -u /dev/$tgt_dev | grep -A1 Device | grep $tgt_dev'1' | awk '{print $3}'`
tgt_part2_field2=`fdisk -l -u /dev/$tgt_dev | grep -A2 Device | grep $tgt_dev'2' | awk '{print $2}'`
tgt_part2_field3=`fdisk -l -u /dev/$tgt_dev | grep -A2 Device | grep $tgt_dev'2' | awk '{print $3}'`
trim_status=`sudo systemctl status fstrim | grep Active | awk '{print $2}'`
#Target information
echo "******************************************"
echo "*          Target Information            *"
echo "******************************************"
echo
echo $(blueprint "Target mount point:") "/dev/$tgt_dev" 
echo $(blueprint "Target device vendor:") "$tgt_dev_vendor" 
echo $(blueprint "Target device model:") "$tgt_dev_model" 
echo $(blueprint "Target device serial:") "$tgt_dev_serial" 
echo $(blueprint "Target device firmware:") "$tgt_dev_firmware" 
echo $(blueprint "Target transport type:") "$tgt_transport"
echo $(blueprint "Target trim status:") "$trim_status"
echo $(blueprint "Target sectors:") "$tgt_sectors"
echo $(blueprint "Target bytes:") "$tgt_bytes"
echo $(blueprint "Target size:") "$tgt_size" 
blocksize=$(fn_calculate_blocksize "$LBASectors")
echo $(blueprint "Target blocksize:") $blocksize | tee -a $output_report
echo
fn_audit_write "target" "mount_point" "/dev/$tgt_dev"
fn_audit_write "target" "vendor" "$tgt_dev_vendor"
fn_audit_write "target" "model" "$tgt_dev_model"
fn_audit_write "target" "serial" "$tgt_dev_serial"
fn_audit_write "target" "firmware" "$tgt_dev_firmware"
fn_audit_write "target" "transport" "$tgt_transport"
fn_audit_write "target" "trim_status" "$trim_status"
fn_audit_write "target" "sectors" "$tgt_sectors"
fn_audit_write "target" "bytes" "$tgt_bytes"
fn_audit_write "target" "size" "$tgt_size"
fn_audit_write "target" "blocksize" "$blocksize"
}


fn_get_diskinfo() {
echo "******************************************"
echo "*           Disk Information             *"
echo "******************************************"
fdisk -l | grep bytes | grep Disk | grep -v veracrypt | grep -v ram | grep -v loop | awk '{print "["$2"]\t"$5" "$6"\t logical blocks: ("$3" "$4")"}' | sed 's/,/./g'
echo "******************************************"
echo
echo -e "** Please enter the mount point of evidence drive (eg. sda): \c "
read evid_dev
echo -e "** Please enter the mount point of target drive (eg. sdb): \c "
read tgt_dev
echo -e "** Please enter the mount point of backup drive (eg. sdc): \c "
read bkp_dev
fn_audit_write "drives" "evidence" "$evid_dev"
fn_audit_write "drives" "target" "$tgt_dev"
fn_audit_write "drives" "backup" "$bkp_dev"
}

fn_encrypt() {
    echo "******************************************"
    echo "*      VeraCrypt Encryption Check        *"
    echo "******************************************"
    veracrypt --version 2>/dev/null | tee -a "$output_report"
    echo "Verifying mounted VeraCrypt volumes..." | tee -a "$output_report"
    veracrypt --text --list 2>/dev/null | tee -a "$output_report"
    fn_audit_write "encryption" "tool" "veracrypt"
}


fn_report_backup() {
bkp_dev_model=`/bin/udevadm info --name=/dev/$bkp_dev | egrep ID_MODEL | awk  -F'[=,]' '{print $2}' | sed -n 1p`
bkp_dev_vendor=`/bin/udevadm info --name=/dev/$bkp_dev | egrep ID_VENDOR | awk  -F'[=,]' '{print $2}' | sed -n 1p`
bkp_dev_serial=`/bin/udevadm info --name=/dev/$bkp_dev | egrep ID_SERIAL_SHORT | awk  -F'[=,]' '{print $2}'`
bkp_dev_firmware=`hdparm -I /dev/$bkp_dev 2>/dev/null | grep -i 'Firmware Revision' | awk '{print $3" "$4" "$5" "$6}'`
LBASectors=`hdparm -g /dev/$bkp_dev | awk -F'[=,]' '{print $4}'`
bkp_transport=`/bin/udevadm info --name=/dev/$bkp_dev | egrep ID_BUS | awk  -F'[=,]' '{print $2}'`
bkp_sectors=`echo $LBASectors | awk '{print $1}'`
bkp_bytes=`fdisk -l -u /dev/$bkp_dev | grep $bkp_dev | grep bytes | awk '{print $5}'`
bkp_size=`fdisk -l -u /dev/$bkp_dev | grep Disk | grep $bkp_dev | awk '{print $3$4}'`
bkp_part_count=`fdisk -l -u /dev/$bkp_dev | grep $bkp_dev | grep -v Disk | wc -l`
bkp_part1_field2=`fdisk -l -u /dev/$bkp_dev | grep -A1 Device | grep $bkp_dev'1' | awk '{print $2}'`
bkp_part1_field3=`fdisk -l -u /dev/$bkp_dev | grep -A1 Device | grep $bkp_dev'1' | awk '{print $3}'`
bkp_part2_field2=`fdisk -l -u /dev/$bkp_dev | grep -A2 Device | grep $bkp_dev'2' | awk '{print $2}'`
bkp_part2_field3=`fdisk -l -u /dev/$bkp_dev | grep -A2 Device | grep $bkp_dev'2' | awk '{print $3}'`
trim_status=`sudo systemctl status fstrim | grep Active | awk '{print $2}'`
#Backup information
echo "******************************************"
echo "*          Backup Information            *"
echo "******************************************"
echo
echo $(blueprint "Backup mount point:") "/dev/$bkp_dev" 
echo $(blueprint "Backup device vendor:") "$bkp_dev_vendor" 
echo $(blueprint "Backup device model:") "$bkp_dev_model" 
echo $(blueprint "Backup device serial:") "$bkp_dev_serial" 
echo $(blueprint "Backup device firmware:") "$bkp_dev_firmware" 
echo $(blueprint "Backup transport type:") "$bkp_transport"
echo $(blueprint "Backup trim status:") "$trim_status"
echo $(blueprint "Backup sectors:") "$bkp_sectors"
echo $(blueprint "Backup bytes:") "$bkp_bytes"
echo $(blueprint "Backup size:") "$bkp_size" 
blocksize=$(fn_calculate_blocksize "$LBASectors")
echo $(blueprint "Backup blocksize:") $blocksize | tee -a $output_report
echo
fn_audit_write "backup" "mount_point" "/dev/$bkp_dev"
fn_audit_write "backup" "vendor" "$bkp_dev_vendor"
fn_audit_write "backup" "model" "$bkp_dev_model"
fn_audit_write "backup" "serial" "$bkp_dev_serial"
fn_audit_write "backup" "firmware" "$bkp_dev_firmware"
fn_audit_write "backup" "transport" "$bkp_transport"
fn_audit_write "backup" "trim_status" "$trim_status"
fn_audit_write "backup" "sectors" "$bkp_sectors"
fn_audit_write "backup" "bytes" "$bkp_bytes"
fn_audit_write "backup" "size" "$bkp_size"
fn_audit_write "backup" "blocksize" "$blocksize"
}




fn_report_working() {
    echo "******************************************"
    echo "*         Working Directory Info         *"
    echo "******************************************"
    pwd | tee -a "$output_report"
    fn_audit_write "working" "pwd" "$(pwd)"
}

fn_report_connected-devices() {
    echo "******************************************"
    echo "*         Connected Devices              *"
    echo "******************************************"
    lsblk | tee -a "$output_report"
    fn_audit_write "devices" "lsblk" "captured"
}

fn_report_mounted-filesystems() {
    echo "******************************************"
    echo "*         Mounted Filesystems            *"
    echo "******************************************"
    findmnt | tee -a "$output_report"
    fn_audit_write "filesystem" "findmnt" "captured"
}
fn_report_available-freespace() {
    echo "******************************************"
    echo "*         Available Free Space           *"
    echo "******************************************"
    df -h | tee -a "$output_report"
    fn_audit_write "filesystem" "df_h" "captured"
}

fn_summary() {
    echo "******************************************"
    echo "*              Summary                   *"
    echo "******************************************"
    echo "Text log: $output_report"
    echo "CSV log : $output_csv"
    echo "JSON log: $output_json"
    echo "TSV log : $output_tsv"
    fn_audit_write "summary" "output_report" "$output_report"
    fn_audit_write "summary" "output_csv" "$output_csv"
    fn_audit_write "summary" "output_json" "$output_json"
    fn_audit_write "summary" "output_tsv" "$output_tsv"
}



function_readme(){
    echo "
Script developed to assist in Forensic collection and reports
With this script you will be able to achieve some goals:
1) Get valuable information about the host
2) Securely save image in encrypted disks
3) Perform forensic imaging in various formats
4) Receive a device collection report

This script has a few assumptions:
1) Use the custodian's computer as the imaging platform
2) Use this script for device collection
3) Have intermediate knowledge in Linux
4) Have target and backup disks, preferably preformatted
5) Use VeraCrypt encryption

Dependencies to run this script:
1) You must install this tools in your distribuition before 
run:
    inxi
    smartctl
    ftkimager
    ddrescue
    dc3dd 
    " | more
}


fn_output_getinfo(){
clear
echo "******************************************"
echo "*        Acquisition Information         *"
echo "******************************************"
echo
echo $(blueprint "First responder:")  $firstname $lastname
echo $(blueprint "Custodian's name:") $custodianFN $custodianLN
echo $(blueprint "Project Name:") $proj_name
echo $(blueprint "Engagement Code (or TBD):") $eng_code
echo $(blueprint "City:") $city1 $city2 $city3 $city4
echo $(blueprint "State:") $state1 $state2 $state3 $state4
echo $(blueprint "Country:") $country
echo $(blueprint "Google Plus Code:") $specific_location
echo
fn_audit_write "acquisition" "first_responder" "$firstname $lastname"
fn_audit_write "acquisition" "custodian" "$custodianFN $custodianLN"
fn_audit_write "acquisition" "project_name" "$proj_name"
fn_audit_write "acquisition" "engagement_code" "$eng_code"
fn_audit_write "acquisition" "city" "$city1 $city2 $city3 $city4"
fn_audit_write "acquisition" "state" "$state1 $state2 $state3 $state4"
fn_audit_write "acquisition" "country" "$country"
fn_audit_write "acquisition" "google_plus_code" "$specific_location"
}

fn_getinfo(){
clear
echo -e "** Please enter YOUR First Name and your Last Name: \c "
read firstname lastname
echo -e "** Please enter the custodian's First Name and Last Name: \c "
read custodianFN custodianLN
echo -e "** Please enter the Project Name: \c "
read proj_name
echo -e "** Please enter the Engagement Code (or TBD): \c "
read eng_code
echo -e "** Please enter the city of acquisition: \c"
read city1 city2 city3 city4
echo -e "** Please enter the state of acquisition: \c "
read state1 state2 state3 state4
echo -e "** Please enter the country of acquisition: \c "
read country
echo -e "** Please enter Google Plus Code (or TBD): \c"
read specific_location
echo -e "** Please enter the Asset Tag Host Information (or N/A): \c "
read host_tag
echo
}

fn_acquire_e01(){
    echo "************************************" | tee -a $output_report
	echo "* FTK Imager Forensic Preservation *" | tee -a $output_report
	echo "************************************" | tee -a $output_report
	echo | tee -a $output_report
	image_start_date=`date +"%A, %B %d, %Y"`
	image_start_time=`date +"%H:%M"`
	echo "Beginning the imaging process with DDRescue Imager on $image_start_date at $image_start_time."
    ftkimager /dev/$evid_dev $tgt_mnt/$evid_barcode/$evid_barcode --verify --no-sha1 --e01 --frag 2G --compress $compress_rate --case-number $evid_barcode --evidence-number $evid_barcode --examiner "$firstname $lastname"
}
fn_acquire_raw(){
    echo "********************************" | tee -a $output_report
	echo "* FTK RAW Forensic Preservation*" | tee -a $output_report
	echo "********************************" | tee -a $output_report
	out="$tgt_mnt/$evid_barcode/$evid_barcode.raw"
    ftkimager /dev/$evid_dev "$out" --verify --raw >> "$output_report" 2>&1 || true
    fn_generate_manifest_hashes "$out"
    fn_audit_write "acquisition" "raw_output" "$out"
}
fn_acquire_aff(){
    echo "**********************************" | tee -a $output_report
	echo "*   AFF Forensic Preservation    *" | tee -a $output_report
	echo "**********************************" | tee -a $output_report
	echo | tee -a $output_report
	image_start_date=`date +"%A, %B %d, %Y"`
	image_start_time=`date +"%H:%M"`
	echo "Beginning the imaging process with DDRescue Imager on $image_start_date at $image_start_time."
    affcopy /dev/$evid_dev $tgt_mnt/$evid_barcode/$evid_barcode.aff
    fn_audit_write "acquisition" "aff_output" "$tgt_mnt/$evid_barcode/$evid_barcode.aff"
}

fn_acquire_img(){
	echo "**********************************" | tee -a $output_report
	echo "* DDRescue Forensic Preservation *" | tee -a $output_report
	echo "**********************************" | tee -a $output_report
	echo | tee -a $output_report
	image_start_date=`date +"%A, %B %d, %Y"`
	image_start_time=`date +"%H:%M"`
	echo "Beginning the imaging process with DDRescue Imager on $image_start_date at $image_start_time."
    ddrescue /dev/$evid_dev $tgt_mnt/$evid_barcode/$evid_barcode.img
}


fn_getdrives(){
echo -e "** Please check the source, target and backup drives (eg. sda sdb sdc): \c "
read host_tag
echo
}

fn_set_forensic_paths
forensic_framework
