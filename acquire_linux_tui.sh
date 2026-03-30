#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# TUI wrapper for acquire_linux.sh workflow.
# Keeps a single-file execution style while minimizing typing errors.

VERSION="2026.03.30"
REGISTER_SECRETS=0
DRY_RUN=0
DISK_DISCOVERY_MODE="both"
SIGN_MODE="hashchain"
GENERATE_SHA256=1

usage() {
  cat <<USAGE
Uso: $0 [opcoes]
  --dry-run
  --allow-secret-logging
  --disk-mode MODE        legacy|modern|both
  --sign-mode MODE        hashchain|gpg|none
  --no-sha256
  -h, --help
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --allow-secret-logging) REGISTER_SECRETS=1 ;;
    --disk-mode=*) DISK_DISCOVERY_MODE="${arg#*=}" ;;
    --sign-mode=*) SIGN_MODE="${arg#*=}" ;;
    --no-sha256) GENERATE_SHA256=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opcao invalida: $arg"; usage; exit 1 ;;
  esac
done

choose_yes_no() {
  local __out_var="$1"
  local prompt_text="$2"
  local answer
  echo "$prompt_text"
  PS3="Selecione: "
  select answer in "Sim" "Nao"; do
    case "$REPLY" in
      1) printf -v "$__out_var" '%s' "y"; return ;;
      2) printf -v "$__out_var" '%s' "n"; return ;;
      *) echo "Opcao invalida" ;;
    esac
  done
}

choose_from_list() {
  local __out_var="$1"
  local prompt_text="$2"
  shift 2
  local options=("$@")
  local answer
  echo "$prompt_text"
  PS3="Selecione: "
  select answer in "${options[@]}"; do
    if [[ -n "${answer:-}" ]]; then
      printf -v "$__out_var" '%s' "$answer"
      return
    fi
    echo "Opcao invalida"
  done
}

prompt_regex() {
  local __out_var="$1"
  local prompt_text="$2"
  local regex="$3"
  local value
  while true; do
    read -r -p "$prompt_text" value
    if [[ "$value" =~ $regex ]]; then
      printf -v "$__out_var" '%s' "$value"
      return
    fi
    echo "Entrada invalida"
  done
}

prompt_secret() {
  local __out_var="$1"
  local prompt_text="$2"
  local value
  read -r -s -p "$prompt_text" value
  echo
  printf -v "$__out_var" '%s' "$value"
}

show_disks_tui() {
  echo "================ DISCOS DETECTADOS ================"
  if [[ "$DISK_DISCOVERY_MODE" == "legacy" || "$DISK_DISCOVERY_MODE" == "both" ]]; then
    echo "--- Legacy: dmesg/fdisk ---"
    dmesg | grep logical | grep blocks || true
    fdisk -l | grep bytes | grep Disk | grep -v -E 'veracrypt|ram|loop' | sed 's/,//g' || true
  fi
  if [[ "$DISK_DISCOVERY_MODE" == "modern" || "$DISK_DISCOVERY_MODE" == "both" ]]; then
    echo "--- Modern: lsblk/blkid ---"
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL || true
    blkid || true
  fi
  echo "==================================================="
}

require_basics() {
  local required=(ftkimager veracrypt ntfslabel rsync xmount smartctl lsblk blkid fdisk dmesg sha256sum md5sum)
  local miss=()
  for c in "${required[@]}"; do
    command -v "$c" >/dev/null 2>&1 || miss+=("$c")
  done
  if [[ "$SIGN_MODE" == "gpg" ]] && ! command -v gpg >/dev/null 2>&1; then
    miss+=("gpg")
  fi
  if (( ${#miss[@]} > 0 )); then
    echo "Dependencias ausentes: ${miss[*]}"
    exit 1
  fi
}

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[DRY-RUN] $*"
  else
    eval "$@"
  fi
}

write_signatures() {
  local summary_file="$1"
  local audit_file="$2"
  local base_dir
  base_dir="$(dirname "$summary_file")"

  if [[ "$SIGN_MODE" == "none" ]]; then
    return
  elif [[ "$SIGN_MODE" == "gpg" ]]; then
    run_cmd "gpg --detach-sign --armor \"$summary_file\""
  else
    {
      echo "artifact|sha256"
      sha256sum "$audit_file" | awk '{print "audit_file|"$1}'
      sha256sum "$summary_file" | awk '{print "summary_file|"$1}'
    } > "$base_dir/hash_chain.log"
  fi
}

main() {
  clear || true
  echo "===================================================="
  echo " acquire_linux_tui.sh v$VERSION"
  echo " Fluxo guiado para aquisicao forense Linux (TUI)"
  echo "===================================================="

  require_basics

  prompt_regex firstname "Seu nome: " '^.{2,}$'
  prompt_regex lastname "Seu sobrenome: " '^.{2,}$'
  prompt_regex custodian_name "Custodiante: " '^.{2,}$'
  prompt_regex proj_name "Projeto: " '^.{2,}$'
  prompt_regex eng_code "Engagement code: " '^.{2,}$'
  prompt_regex location "Local: " '^.{2,}$'

  show_disks_tui
  prompt_regex evid_dev "Device da evidencia (ex: sda): " '^sd[a-z]+$'
  prompt_regex evid_id "Evidence ID da evidencia: " '^[A-Za-z0-9._-]+$'

  show_disks_tui
  prompt_regex tgt_dev "Device do target (ex: sdb): " '^sd[a-z]+$'
  prompt_regex tgt_id "Evidence ID do target: " '^[A-Za-z0-9._-]+$'
  prompt_regex compress_rate "Compressao FTK [0-9]: " '^[0-9]$'
  prompt_secret tgt_pw "Senha VeraCrypt target: "

  choose_yes_no backup_drive "Deseja usar disco de backup?"
  if [[ "$backup_drive" == "y" ]]; then
    show_disks_tui
    prompt_regex bkup_dev "Device do backup (ex: sdc): " '^sd[a-z]+$'
    prompt_regex bkup_id "Evidence ID do backup: " '^[A-Za-z0-9._-]+$'
    prompt_secret bkup_pw "Senha VeraCrypt backup: "
  fi

  choose_from_list go_now "Confirma inicio da imagem?" "Iniciar" "Cancelar"
  [[ "$go_now" == "Iniciar" ]] || { echo "Cancelado"; exit 0; }

  curr_stamp="$(date +"%Y%m%d.%H%M%S")"
  curr_date="$(date +"%A, %B %d, %Y")"
  curr_time="$(date +"%H:%M")"
  curr_utc="$(date -u +"%Y-%m-%d %H:%M %:::z %Z")"

  run_cmd "ntfslabel /dev/${tgt_dev}1 \"$tgt_id\""
  run_cmd "veracrypt --filesystem=ntfs-3g --password=\"$tgt_pw\" --slot=1 /dev/${tgt_dev}2"
  tgt_mnt="/media/veracrypt1"
  target_case_dir="$tgt_mnt/$evid_id"
  run_cmd "mkdir -p \"$target_case_dir\""

  audit_file="$target_case_dir/${evid_id}.${curr_stamp}.wri"
  summary_file="$target_case_dir/${evid_id}.summary.tsv"
  metalog="$target_case_dir/${evid_id}.metalog.log"

  {
    echo "*** BEGIN FTK Acquisition Audit File for $evid_id ***"
    echo "Forensic Examiner Name: $firstname $lastname"
    echo "Project Name: $proj_name"
    echo "Engagement Code: $eng_code"
    echo "Custodian Name: $custodian_name"
    echo "Place of Acquisition: $location"
    echo "Current Date: $curr_date"
    echo "Current Time: $curr_time"
    echo "UTC DateTime: $curr_utc"
    echo "uname: $(uname -a)"
  } | tee -a "$audit_file"

  ftk_cmd="ftkimager /dev/$evid_dev $target_case_dir/$evid_id --verify --no-sha1 --e01 --frag 2G --compress $compress_rate --case-number $evid_id --evidence-number $evid_id --examiner \"$firstname $lastname\""
  echo "$ftk_cmd" | tee -a "$audit_file"
  run_cmd "$ftk_cmd"

  first_image=$(ls -1 "$target_case_dir"/*.E* 2>/dev/null | head -n1 || true)
  md5_hash="N/A"
  sha256_hash="N/A"
  if [[ -n "$first_image" ]]; then
    md5_hash=$(md5sum "$first_image" | awk '{print $1}')
    if [[ "$GENERATE_SHA256" -eq 1 ]]; then
      sha256_hash=$(sha256sum "$first_image" | awk '{print $1}')
    fi
  fi

  if [[ "$backup_drive" == "y" ]]; then
    run_cmd "ntfslabel /dev/${bkup_dev}1 \"$bkup_id\""
    run_cmd "veracrypt --filesystem=ntfs-3g --password=\"$bkup_pw\" --slot=2 /dev/${bkup_dev}2"
    bkup_mnt="/media/veracrypt2"
    backup_case_dir="$bkup_mnt/$evid_id"
    run_cmd "mkdir -p \"$backup_case_dir\""
    rsync_log="$backup_case_dir/${evid_id}.rsynclog.${curr_stamp}.wri"
    run_cmd "rsync -v -t -P --stats --log-file=\"$rsync_log\" --log-file-format=\"%t  %f  %M  %l\" \"$target_case_dir\"/* \"$backup_case_dir\""
  fi

  {
    echo -e "Drive\tEvidence ID\tDevice\tMD5_Hash\tSHA256_Hash"
    echo -e "Evidence\t$evid_id\t$evid_dev\t$md5_hash\t$sha256_hash"
    echo -e "Target\t$tgt_id\t$tgt_dev\t$md5_hash\t$sha256_hash"
    if [[ "$backup_drive" == "y" ]]; then
      echo -e "Backup\t$bkup_id\t$bkup_dev\t$md5_hash\t$sha256_hash"
    fi
  } | tee "$summary_file"

  {
    echo "auditfile|$audit_file"
    echo "backup_drive|$backup_drive"
    echo "curr_date|$curr_date"
    echo "curr_time|$curr_time"
    echo "evid_Evidence ID|$evid_id"
    echo "tgt_Evidence ID|$tgt_id"
    echo "bkup_Evidence ID|${bkup_id:-}"
    if [[ "$REGISTER_SECRETS" -eq 1 ]]; then
      echo "tgt_pw|$tgt_pw"
      echo "bkup_pw|${bkup_pw:-}"
    else
      echo "tgt_pw|[REDACTED]"
      echo "bkup_pw|[REDACTED]"
    fi
  } > "$metalog"

  write_signatures "$summary_file" "$audit_file"

  if [[ "$backup_drive" == "y" ]]; then
    run_cmd "cp \"$metalog\" \"$backup_case_dir\"/"
    run_cmd "cp \"$summary_file\" \"$backup_case_dir\"/"
  fi

  echo "*** END FTK Acquisition Audit File for $evid_id ***" | tee -a "$audit_file"
  echo "Concluido com sucesso."
  echo "Audit: $audit_file"
  echo "Summary: $summary_file"
  echo "Metalog: $metalog"
}

main
