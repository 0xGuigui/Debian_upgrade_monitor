#!/bin/bash

set -Eeuo pipefail
umask 077

# ==============================================================================
# DEBIAN UPGRADE MONITOR v2.9.5
# Written by 0xGuigui
# ==============================================================================
# System state monitoring script for pre/post upgrade.
# Usage: sudo ./upgrade_monitor.sh
# ==============================================================================

# --- CONFIGURATION ---
VERSION="2.9.5"
STATE_DIR="/var/lib/debian-upgrade-monitor"
DRY_RUN=0
VERBOSE=0
JSON_REPORT=""
LOCK_FILE=""
LOCK_FD=""
LOCK_HELD=0
CURRENT_STATUS="EXCELLENT"
CLEANUP=0
OS_FLAVOR="unknown"
declare -a ISSUE_PENALTIES=()
declare -a ISSUE_REASONS=()

# Global Score (Starting at 100)
SCORE=100
MAX_SCORE=100

# Display language (default English, French if system locale is French)
UI_LANG="en"

detect_ui_language() {
    local raw_locale="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$raw_locale" ] && command -v locale >/dev/null 2>&1; then
        raw_locale=$(locale 2>/dev/null | awk -F= '/^LANG=/{print $2}')
    fi
    raw_locale=$(echo "$raw_locale" | tr '[:upper:]' '[:lower:]')
    if [[ "$raw_locale" == fr* ]]; then
        UI_LANG="fr"
    fi
}

translate() {
    local en="$1"
    local fr="$2"
    if [ "$UI_LANG" = "fr" ]; then
        printf "%s" "$fr"
    else
        printf "%s" "$en"
    fi
}

detect_os_flavor() {
    local os_release="/etc/os-release"
    local id=""
    local lsb_id=""
    local pretty=""

    if [ -f "$os_release" ]; then
        id=$(awk -F= '/^ID=/{gsub(/"/,"",$2);print tolower($2)}' "$os_release")
        pretty=$(awk -F= '/^PRETTY_NAME=/{sub(/^"/,"",$2);sub(/"$/,"",$2);print $2}' "$os_release")
    fi

    if command -v lsb_release >/dev/null 2>&1; then
        lsb_id=$(lsb_release -is 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    fi

    if [ -z "$pretty" ] && [ -f /etc/issue ]; then
        pretty=$(head -n 1 /etc/issue | sed 's/\\\\[a-z]//gi' | xargs)
    fi

    if [ "$id" = "debian" ] || [ "$lsb_id" = "debian" ]; then
        OS_FLAVOR="debian"
        return 0
    fi

    if [ -f /etc/debian_version ] && [ -z "$id" ] && [ -z "$lsb_id" ]; then
        OS_FLAVOR="debian"
        return 0
    fi

    if [ -n "$pretty" ]; then
        OS_FLAVOR="$pretty"
    elif [ -n "$id" ]; then
        OS_FLAVOR="$id"
    elif [ -n "$lsb_id" ]; then
        OS_FLAVOR="$lsb_id"
    else
        OS_FLAVOR="unknown"
    fi
    return 1
}

enforce_debian() {
    if detect_os_flavor; then
        return
    fi

    local detected="$OS_FLAVOR"
    if [ "$detected" = "unknown" ]; then
        detected=$(translate "unknown OS" "OS inconnu")
    fi

    local msg
    msg=$(translate "Detected '$detected'. This script currently supports Debian only (maybe more platforms in the future)." "Détection : '$detected'. Ce script n'est actuellement compatible qu'avec Debian (peut-être d'autres plateformes à l'avenir).")

    if [ -n "${RED-}" ]; then
        echo -e "${RED}[$(translate "ERROR" "ERREUR")] $msg${NC}"
    else
        echo "[$(translate "ERROR" "ERREUR")] $msg"
    fi
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./upgrade_monitor.sh [options]

Options:
  --dry-run             Run in read-only mode (skip cleanup and interactive edits)
  -v, --verbose        Enable verbose diagnostic output
  --json-report PATH   Write JSON summary to the provided file
  --state-dir PATH     Override the default state directory
  --cleanup            Remove snapshots after analysis (legacy behavior)
  -h, --help           Show this help text and exit
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                ;;
            -v|--verbose)
                VERBOSE=1
                ;;
            --json-report)
                if [ -z "${2:-}" ]; then
                    echo "--json-report requires a path." >&2
                    exit 1
                fi
                JSON_REPORT="$2"
                shift
                ;;
            --state-dir)
                if [ -z "${2:-}" ]; then
                    echo "--state-dir requires a path." >&2
                    exit 1
                fi
                STATE_DIR="$2"
                shift
                ;;
            --cleanup)
                CLEANUP=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done
}

validate_state_dir() {
    if [ -z "$STATE_DIR" ]; then
        echo "STATE_DIR cannot be empty." >&2
        exit 1
    fi
    if [[ "$STATE_DIR" != /* ]]; then
        echo "STATE_DIR must be an absolute path." >&2
        exit 1
    fi
    if [ "$STATE_DIR" = "/" ]; then
        echo "STATE_DIR cannot be /." >&2
        exit 1
    fi

    if command -v python3 >/dev/null 2>&1; then
        STATE_DIR=$(python3 - "$STATE_DIR" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
)
    fi
}

prepare_state_dir() {
    local mode="${1:-require}"
    if [ -d "$STATE_DIR" ]; then
        chmod 700 "$STATE_DIR"
        chown root:root "$STATE_DIR" >/dev/null 2>&1 || true
        return
    fi

    if [ "$mode" = "create" ]; then
        install -d -m 700 "$STATE_DIR"
        chown root:root "$STATE_DIR" >/dev/null 2>&1 || true
    else
        log_error "$(translate "State directory missing." "Répertoire d'état manquant.")"
        exit 1
    fi
}

compute_lock_file() {
    local hashed
    if command -v md5sum >/dev/null 2>&1; then
        hashed=$(printf '%s' "$STATE_DIR" | md5sum | awk '{print $1}')
    else
        hashed=$(printf '%s' "$STATE_DIR" | cksum | awk '{print $1}')
    fi
    if [ -z "$hashed" ]; then
        hashed="default"
    fi
    LOCK_FILE="/var/lock/debian-upgrade-monitor-${hashed}.lock"
}

acquire_lock() {
    local lock_dir
    lock_dir=$(dirname "$LOCK_FILE")
    mkdir -p "$lock_dir"
    exec {LOCK_FD}>"$LOCK_FILE"
    if ! flock -n "$LOCK_FD"; then
        echo "Another instance of the monitor is already running." >&2
        exit 1
    fi
    LOCK_HELD=1
}

cleanup() {
    local exit_code=$1
    if [ "$LOCK_HELD" -eq 1 ] && [ -n "${LOCK_FD:-}" ]; then
        flock -u "$LOCK_FD"
        rm -f "$LOCK_FILE"
    fi
}

on_error() {
    local code=$1
    local line=$2
    local last_cmd=${BASH_COMMAND:-}
    if [[ "$last_cmd" == exit* ]]; then
        return
    fi
    log_error "$(translate "Unexpected error (code $code) at line $line." "Erreur inattendue (code $code) à la ligne $line.")"
}

escape_json_string() {
    local input="$1"
    input=${input//\\/\\\\}
    input=${input//"/\\"}
    input=${input//$'\n'/\\n}
    input=${input//$'\r'/\\r}
    printf '%s' "$input"
}

preview_change_sample() {
    local -n arr_ref=$1
    local limit=${2:-5}
    local count=${#arr_ref[@]}
    if [ "$count" -eq 0 ]; then
        printf 'n/a'
        return
    fi
    if [ "$VERBOSE" -eq 1 ] || [ "$count" -le "$limit" ]; then
        printf '%s' "${arr_ref[*]}"
    else
        local snippet=("${arr_ref[@]:0:$limit}")
        printf '%s...' "${snippet[*]}"
    fi
}

write_json_report() {
    local target="$1"
    [ -z "$target" ] && return
    local dir
    dir=$(dirname "$target")
    mkdir -p "$dir"

    local issues_json="[]"
    if [ ${#ISSUE_PENALTIES[@]} -gt 0 ]; then
        local entries=()
        local idx=0
        for penalty in "${ISSUE_PENALTIES[@]}"; do
            local reason="${ISSUE_REASONS[$idx]}"
            local escaped_reason
            escaped_reason=$(escape_json_string "$reason")
            entries+=("{\"penalty\":$penalty,\"reason\":\"$escaped_reason\"}")
            ((idx+=1))
        done
        local joined=$(printf '%s,' "${entries[@]}")
        joined=${joined%,}
        issues_json="[$joined]"
    fi

    cat >"$target" <<EOF
{
  "timestamp": "$(date --iso-8601=seconds)",
  "score": $SCORE,
  "status": "$CURRENT_STATUS",
  "stateDirectory": "$STATE_DIR",
  "issues": $issues_json
}
EOF
    log_verbose "JSON report saved to $target"
}

report_package_changes() {
    local prev_versions="$STATE_DIR/prev_pkg_versions"
    local curr_versions="$STATE_DIR/curr_pkg_versions"

    if [ ! -f "$prev_versions" ] || [ ! -f "$curr_versions" ]; then
        log_warn "$(translate "Package version snapshot missing; skipping package diff." "Instantané des versions de paquets manquant ; comparaison ignorée.")"
        return
    fi

    mapfile -t added_list < <(awk -F'\t' 'NR==FNR { prev[$1]=$2; next } { if (!($1 in prev)) print $1"="$2 }' "$prev_versions" "$curr_versions")
    mapfile -t removed_list < <(awk -F'\t' 'NR==FNR { curr[$1]=$2; next } { if (!($1 in curr)) print $1"="$2 }' "$curr_versions" "$prev_versions")
    mapfile -t changed_list < <(awk -F'\t' 'NR==FNR { prev[$1]=$2; next } ($1 in prev && prev[$1]!=$2) { print $1"="prev[$1]" -> "$2 }' "$prev_versions" "$curr_versions")

    local added_count=${#added_list[@]}
    local removed_count=${#removed_list[@]}
    local changed_count=${#changed_list[@]}

    if [ "$added_count" -gt 0 ]; then
        local sample=$(preview_change_sample added_list)
        log_warn "$(translate "$added_count packages newly installed: $sample" "$added_count paquets nouvellement installés : $sample")"
    else
        log_success "$(translate "No new packages installed since baseline." "Aucun nouveau paquet installé depuis la baseline.")"
    fi

    if [ "$removed_count" -gt 0 ]; then
        local sample_rm=$(preview_change_sample removed_list)
        log_warn "$(translate "$removed_count packages removed: $sample_rm" "$removed_count paquets supprimés : $sample_rm")"
        update_score 3 "Packages Removed"
    else
        log_success "$(translate "No baseline packages were removed." "Aucun paquet de la baseline n'a été supprimé.")"
    fi

    if [ "$changed_count" -gt 0 ]; then
        local sample_ch=$(preview_change_sample changed_list)
        log_warn "$(translate "$changed_count packages changed versions: $sample_ch" "$changed_count paquets ont changé de version : $sample_ch")"
        update_score 2 "Package Versions Changed"
    else
        log_success "$(translate "No package version drift detected." "Aucune dérive de version détectée.")"
    fi
}

detect_ui_language

parse_args "$@"
validate_state_dir

if [ -z "$JSON_REPORT" ]; then
    JSON_REPORT="$STATE_DIR/last_report.json"
fi

# Force locale to C to avoid bugs (grep/sort/apt), display remains translated
export LC_ALL=C
export LANG=C

# Colors & Style
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

enforce_debian

# Root Verification
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[$(translate "ERROR" "ERREUR")] $(translate "This script must be run as root." "Ce script doit être exécuté avec les privilèges root.")${NC}"
  exit 1
fi

compute_lock_file
acquire_lock
trap 'cleanup $?' EXIT
trap 'on_error $? $LINENO' ERR

# --- SCORE FUNCTIONS ---

update_score() {
    local penalty=$1
    local reason=$2
    SCORE=$((SCORE - penalty))
    if [ $SCORE -lt 0 ]; then SCORE=0; fi
    if [ -n "$reason" ]; then
        ISSUE_PENALTIES+=("$penalty")
        ISSUE_REASONS+=("$reason")
    fi
}

display_score() {
    echo -e "\n======================================================"
    echo -e "   $(translate "SYSTEM AUDIT RESULT" "RÉSULTAT DE L'AUDIT SYSTÈME")"
    echo -e "======================================================"
    
    local color=$GREEN
    local status
    local status_key="EXCELLENT"
    status=$(translate "EXCELLENT" "EXCELLENT")

    if [ $SCORE -lt 90 ]; then
        color=$YELLOW
        status=$(translate "WARNING" "ATTENTION")
        status_key="WARNING"
    fi
    if [ $SCORE -lt 70 ]; then
        color=$RED
        status=$(translate "CRITICAL" "CRITIQUE")
        status_key="CRITICAL"
    fi

    CURRENT_STATUS="$status_key"

    echo -e "$(translate "OVERALL SCORE" "SCORE GLOBAL") : ${color}${BOLD}${SCORE} / 100${NC} ($status)"
    
    local filled=$((SCORE / 2))
    local empty=$((50 - filled))
    printf "%s : [" "$(translate "Status" "État")"
    printf "%0.s#" $(seq 1 $filled)
    printf "%0.s." $(seq 1 $empty)
    printf "]\n\n"

    if [ $SCORE -eq 100 ]; then
        echo -e "${GREEN}$(translate "Great! System is clean, up to date and stable." "Félicitations ! Le système est propre, à jour et stable.")${NC}"
    elif [ $SCORE -gt 80 ]; then
        echo -e "${YELLOW}$(translate "Good job. Minor cleanups are recommended." "Bon travail. Quelques nettoyages mineurs sont conseillés.")${NC}"
    else
        echo -e "${RED}$(translate "Warning. Service or configuration issues require attention." "Attention. Des problèmes de services ou de configuration nécessitent une intervention.")${NC}"
    fi
    
    # History
    if [ -d "$STATE_DIR" ] && [ "$DRY_RUN" -eq 0 ]; then
        echo "$(date +'%Y-%m-%d %H:%M:%S') | SCORE=$SCORE | $status" >> "$STATE_DIR/history.log"
    fi
    echo "--------------------------------------------------------"
}

# --- LOGGING FUNCTIONS ---

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_clean() { echo -e "${PURPLE}[CLEAN]${NC} $1"; }
log_verbose() { if [ "$VERBOSE" -eq 1 ]; then echo -e "${CYAN}[VERBOSE]${NC} $1"; fi }

print_header() {
    clear
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BOLD}   $(translate "DEBIAN UPGRADE MONITOR (v$VERSION)" "MONITEUR DE MISE À JOUR DEBIAN (v$VERSION)")${NC}"
    echo -e "   $(translate "Written by 0xGuigui" "Écrit par 0xGuigui")"
    echo -e "${BLUE}======================================================${NC}"
    echo ""
}

# --- COMPARISON HELPER ---
get_diff() {
    if [ ! -f "$1" ] || [ ! -f "$2" ]; then echo ""; return; fi
    comm -23 <(sort "$1") <(sort "$2")
}

# --- SAFE READ HELPER ---
get_val() {
    local file="$1"
    local key="$2"
    local default="$3"
    if [ -f "$file" ]; then
        local val=$(grep "^$key=" "$file" | cut -d= -f2)
        if [ -z "$val" ]; then echo "$default"; else echo "$val"; fi
    else echo "$default"; fi
}

# --- SERVICE CHECK ---

smart_service_check() {
    local missing_list="$1"
    local current_file="$2"
    local truly_missing_count=0

    local current_services_content
    current_services_content=$(cat "$current_file")

    echo -e "${BOLD}   >>> $(translate "Smart analysis of missing services:" "Analyse intelligente des services disparus :")${NC}"

    while IFS= read -r old_svc; do
        [ -z "$old_svc" ] && continue
        
        local clean_name=$(echo "$old_svc" | sed -E 's/\.service$//')
        local stem=$(echo "$clean_name" | sed -E 's/[0-9\.]+//g; s/-//g; s/@.*//g')

        # HEURISTIC 0: Whitelist (Oneshot / Boot services)
        if [[ "$clean_name" =~ ^(sysstat|console-setup|keyboard-setup|kmod-static-nodes|systemd-sysusers|systemd-fsck|ifup|networking)$ ]]; then
             echo -e "   -> ${GREEN}[BOOT/ONESHOT]${NC} $old_svc $(translate "(Normal startup service)" "(Service de démarrage normal)")"
             continue
        fi

        local candidate=""

        # HEURISTIC 1 & 2: PHP/Postgres Versions
        if [[ "$old_svc" =~ php.*fpm ]]; then
            candidate=$(grep -Ei -m1 "php.*fpm" <<< "$current_services_content" || true)
        fi
        if [[ "$old_svc" =~ postgresql ]]; then
            candidate=$(grep -Ei -m1 "postgresql" <<< "$current_services_content" || true)
        fi

        # HEURISTIC 3: Fuzzy Match & Alias
        if [ -z "$candidate" ]; then
            candidate=$(grep -Fi -m1 -- "$stem" <<< "$current_services_content" || true)
            if [ -z "$candidate" ] && [[ "$stem" == *"phpfpm"* ]]; then
                candidate=$(grep -Ei -m1 "php.*fpm" <<< "$current_services_content" || true)
            fi
            
            if [ -z "$candidate" ]; then
                case "$stem" in
                    "mysql") candidate=$(grep -Fi -m1 "mariadb" <<< "$current_services_content" || true) ;;
                    "mariadb") candidate=$(grep -Fi -m1 "mysql" <<< "$current_services_content" || true) ;;
                    "cron") candidate=$(grep -Fi -m1 "systemd-cron" <<< "$current_services_content" || true) ;;
                    "ntp") candidate=$(grep -Fi -m1 "systemd-timesyncd" <<< "$current_services_content" || true) ;;
                esac
            fi
        fi

        if [ -n "$candidate" ]; then
            echo -e "   -> ${CYAN}[MIGRATED]${NC} $old_svc $(translate "seems to be replaced by" "semble être devenu") ${GREEN}$candidate${NC}"
        else
            echo -e "   -> ${RED}[MISSING]  $old_svc${NC} $(translate "(No equivalent found)" "(Aucun équivalent trouvé)")"
            ((truly_missing_count+=1))
        fi

    done <<< "$missing_list"

    return $truly_missing_count
}

# --- CONFLICT RESOLVER ---

resolve_conflicts() {
    local conflicts="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        log_warn "$(translate "Dry-run mode: conflict resolver is disabled." "Mode simulation : le résolveur de conflits est désactivé.")"
        return
    fi
    echo -e "\n${BOLD}>>> $(translate "STARTING INTERACTIVE CONFLICT RESOLVER" "DÉMARRAGE DU RÉSOLVEUR INTERACTIF")${NC}"
    echo "$(translate "For each file, choose an action." "Pour chaque fichier, choisissez une action.")"
    
    while IFS= read -r conflict_file; do
        [ -z "$conflict_file" ] && continue
        real_file="${conflict_file%.dpkg-*}"
        real_file="${real_file%.ucf-*}"

        while true; do
            echo -e "\n--------------------------------------------------------"
            echo -e "$(translate "CONFLICT" "CONFLIT") : ${BOLD}$real_file${NC}"
            echo -e "$(translate "NEW" "NOUVEAU") : ${YELLOW}$conflict_file${NC}"
            echo -e "$(translate "CURRENT" "ACTUEL")  : ${GREEN}$real_file${NC}"
            echo "--------------------------------------------------------"
            echo -e "$(translate "[${BOLD}D${NC}] Diff  [${BOLD}K${NC}] Keep  [${BOLD}R${NC}] Replace  [${BOLD}E${NC}] Edit  [${BOLD}S${NC}] Skip  [${BOLD}Q${NC}] Quit" "[${BOLD}D${NC}] Diff  [${BOLD}K${NC}] Conserver  [${BOLD}R${NC}] Remplacer  [${BOLD}E${NC}] Éditer  [${BOLD}S${NC}] Passer  [${BOLD}Q${NC}] Quitter")"
            
            if read -e -p "$(translate "Action? : " "Action ? : ")" choice < /dev/tty; then :; else echo "$(translate "TTY error." "Erreur TTY.")"; return; fi
            choice=${choice,,}; choice=${choice:0:1}
            
            case "$choice" in 
                d) if command -v colordiff >/dev/null 2>&1; then colordiff -u "$real_file" "$conflict_file" | less -R || true; else diff -u --color=auto "$real_file" "$conflict_file" | less -R || true; fi ;;
                k) rm "$conflict_file"; log_success "$(translate "Cleaned." "Nettoyé.")"; break ;;
                r)
                    if [ -e "$real_file" ]; then
                        cp "$real_file" "$real_file.bak"
                    fi
                    mv "$conflict_file" "$real_file"
                    log_success "$(translate "Updated." "Mis à jour.")"
                    break
                    ;;
                e) ${EDITOR:-nano} "$real_file" "$conflict_file"; echo -e "${YELLOW}$(translate "Handle the files manually." "Gérez les fichiers manuellement.")${NC}"; break ;;
                s) echo " -> $(translate "Skipped." "Ignoré.")"; break ;;
                q) echo " -> $(translate "Stopped." "Arrêt.")"; return ;;
                *) echo "$(translate "Invalid choice." "Choix invalide.")";;
            esac
        done
    done <<< "$conflicts"
}

# --- DATA COLLECTION FUNCTIONS ---

get_services() { 
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=active --no-legend --plain | awk '{print $1}' | \
        grep -vE "^(lvm2-pvscan@|systemd-fsck@|user@|user-runtime-dir@|session-[a-z0-9]+\.scope|ifup@|systemd-sysusers|systemd-update-utmp|sysstat|keyboard-setup|console-setup)" | \
        sort
    elif command -v service >/dev/null 2>&1; then
        # SysVinit / Upstart fallback
        service --status-all 2>&1 | grep "+" | awk '{print $4}' | sort
    else
        ls /etc/init.d/ 2>/dev/null | sort
    fi
}

get_timers() { 
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=timer --state=active --no-legend --plain | awk '{print $1}' | sort
    else
        echo "no-systemd-timers"
    fi
}

get_mounts() { mount | grep -E "^/dev/" | awk '{print $3}' | sort; }
get_packages() { dpkg --get-selections | sort; }
get_kernel() { uname -r; }
get_debian_version() { cat /etc/debian_version; }
get_dns() { grep "^nameserver" /etc/resolv.conf | sort; }

get_ports() {
    # Normalization: PROTOCOL LOCAL_IP:PORT PROCESS_NAME
    if command -v ss >/dev/null 2>&1; then
        # ss output: Netid State Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process
        # Extract $1 (Proto), $5 (Local), and clean $7 (Process)
        # users:(("nginx",pid=123,fd=4)) -> nginx
        # Also normalize IPv6 [::] -> :: to match netstat if needed
        ss -tulpn | awk 'NR>1 {print $1, $5, $7}' | \
        sed -E 's/users:\(\("([^"]+)".*/\1/; s/\[::\]/::/g' | \
        sort
    elif command -v netstat >/dev/null 2>&1; then
        # netstat output: Proto Recv-Q Send-Q Local Address ... PID/Program name
        # Take $1, $4 and the last field $NF (PID/Name)
        # 123/nginx -> nginx
        netstat -tulpn | awk 'NR>2 {print $1, $4, $NF}' | \
        sed -E 's/^[0-9]+\///' | \
        sort
    fi
}

# --- NEW v2.5: CLEANUP & MAINTENANCE ---

check_cleanup() {
    local issues=0
    
    # 1. Autoremove check
    # Simulate (-s) and count lines starting with "Remv" (remove)
    local autoremove_count
    autoremove_count=$(apt-get -s autoremove | awk '/^Remv/{c++} END{print c+0}')
    
    if [ "$autoremove_count" -gt 0 ]; then
        log_clean "$(translate "$autoremove_count unused packages detected (orphan dependencies)." "$autoremove_count paquets inutiles détectés (dépendances orphelines).")"
        echo -e "   -> ${CYAN}$(translate "Tip: consider a backup first (e.g. apt-clone)." "Conseil : Pensez à faire un backup avant (ex: apt-clone).")${NC}"
        echo -e "   -> $(translate "Suggested command" "Commande suggérée") : ${BOLD}apt autoremove --purge${NC}"
        update_score 2 "Need Autoremove"
        ((issues+=1))
    else
        log_success "$(translate "No unused packages (Autoremove clean)." "Aucun paquet inutile (Autoremove propre).")"
    fi

    # 2. RC Packages (Residual Config)
    # These are packages that have been removed but their config files remain
    local rc_count
    rc_count=$(dpkg -l | awk '/^rc/{c++} END{print c+0}')
    
    if [ "$rc_count" -gt 0 ]; then
        log_clean "$(translate "$rc_count 'ghost packages' (RC - Residual Config) detected." "$rc_count 'paquets fantômes' (RC - Residual Config) détectés.")"
        echo -e "   -> $(translate "Suggested command" "Commande suggérée") : ${BOLD}apt purge \$(dpkg -l | grep '^rc' | awk '{print \$2}')${NC}"
        update_score 1 "RC Packages"
        ((issues+=1))
    else
        log_success "$(translate "No configuration residues (RC clean)." "Aucun résidu de configuration (RC propre).")"
    fi

    # 3. Old Kernels
    # Count installed linux images
    local kernel_count
    kernel_count=$(dpkg -l | awk '/^ii/ && /linux-image-[0-9]/{c++} END{print c+0}')
    if [ "$kernel_count" -gt 2 ]; then
        log_warn "$(translate "Several kernels installed: $kernel_count (may fill /boot)." "Nombreux noyaux installés : $kernel_count (Peut saturer /boot).")"
        echo -e "   -> $(translate "Suggested command" "Commande suggérée") : ${BOLD}apt autoremove --purge${NC} $(translate "(should clean them up)" "(devrait les nettoyer)")"
        # No score penalty, just a warning
    fi
    
    # 4. Reboot required?
    if [ -f /var/run/reboot-required ]; then
        log_warn "$(translate "A system reboot is REQUIRED (/var/run/reboot-required present)." "Un redémarrage système est REQUIS (/var/run/reboot-required présent).")"
        update_score 5 "Reboot Required"
    fi
}

# --- WEB & APP INTELLIGENCE ---

check_web_health() {
    if command -v nginx >/dev/null 2>&1; then
        echo "NGINX_INSTALLED=1"
        if nginx -t >/dev/null 2>&1; then echo "NGINX_CONF=OK"; else echo "NGINX_CONF=FAIL"; fi
    else echo "NGINX_INSTALLED=0"; fi

    if command -v apache2ctl >/dev/null 2>&1; then
        echo "APACHE_INSTALLED=1"
        if apache2ctl configtest >/dev/null 2>&1; then echo "APACHE_CONF=OK"; else echo "APACHE_CONF=FAIL"; fi
    else echo "APACHE_INSTALLED=0"; fi

    if command -v curl >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then
            HTTP_CODE=$(timeout 5 curl -s -o /dev/null -w "%{http_code}" http://localhost || echo "000")
        else
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost || echo "000")
        fi
    else
        HTTP_CODE="NO_CURL"
    fi
    echo "HTTP_LOCALHOST_CODE=$HTTP_CODE"
}

check_php_health() {
    if command -v php >/dev/null 2>&1; then
        PHP_VER=$(php -v | head -n 1 | awk '{print $2}')
        echo "PHP_VERSION=$PHP_VER"
        php -m | sort > "$STATE_DIR/temp_php_modules"
    else echo "PHP_VERSION=NONE"; fi
}

check_db_health() {
    if command -v mysqladmin >/dev/null 2>&1; then
        if mysqladmin ping --silent >/dev/null 2>&1; then echo "MYSQL_PING=OK"; else echo "MYSQL_PING=FAIL"; fi
    else echo "MYSQL_PING=NA"; fi

    if command -v pg_isready >/dev/null 2>&1; then
        if pg_isready -q >/dev/null 2>&1; then echo "PGSQL_PING=OK"; else echo "PGSQL_PING=FAIL"; fi
    else echo "PGSQL_PING=NA"; fi
}

check_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        UFW_STATUS=$(ufw status | grep "Status" | awk '{print $2}')
        echo "UFW_STATUS=$UFW_STATUS"
    else echo "UFW_STATUS=NA"; fi
    
    if command -v nft >/dev/null 2>&1; then
        NFT_RULES=$(nft list ruleset | wc -l)
        echo "NFT_RULES_COUNT=$NFT_RULES"
    else echo "NFT_RULES_COUNT=NA"; fi
}

# --- MODE 1: BEFORE UPGRADE (CAPTURE) ---

collect_pre_upgrade() {
    print_header
    if [ "$DRY_RUN" -eq 1 ]; then
        log_error "$(translate "Dry-run mode cannot initialize the baseline capture." "Le mode simulation ne peut pas initialiser la capture de référence.")"
        exit 1
    fi
    log_info "$(translate "No existing baseline. Starting pre-upgrade capture." "État initial inexistant. Démarrage de la capture pré-mise à jour.")"
    echo "$(translate "Storage directory" "Répertoire de stockage") : $STATE_DIR"
    prepare_state_dir create
    echo "$VERSION" > "$STATE_DIR/script_version"

    log_info "$(translate "Saving OS and kernel versions..." "Sauvegarde version OS et Kernel...")"
    get_debian_version > "$STATE_DIR/prev_os_version"
    get_kernel > "$STATE_DIR/prev_kernel"

    log_info "$(translate "Running full inventory (Services, Ports, Web, PHP, DB, Firewall)..." "Inventaire complet (Services, Ports, Web, PHP, DB, Firewall)...")"
    get_services > "$STATE_DIR/prev_services"
    get_timers > "$STATE_DIR/prev_timers"
    get_ports > "$STATE_DIR/prev_ports"
    get_mounts > "$STATE_DIR/prev_mounts"
    get_dns > "$STATE_DIR/prev_dns"
    get_packages > "$STATE_DIR/prev_packages"
    dpkg-query -W -f '${Package}\t${Version}\n' | sort > "$STATE_DIR/prev_pkg_versions"
    ip route show > "$STATE_DIR/prev_routes"

    check_web_health > "$STATE_DIR/prev_web_health"
    check_php_health > "$STATE_DIR/prev_php_health"
    if [ -f "$STATE_DIR/temp_php_modules" ]; then mv "$STATE_DIR/temp_php_modules" "$STATE_DIR/prev_php_modules"; fi
    check_db_health > "$STATE_DIR/prev_db_health"
    check_firewall > "$STATE_DIR/prev_firewall"

    echo ""
    log_success "$(translate "Capture completed (Script Version: $VERSION)." "Capture terminée (Version Script: $VERSION).")"
    echo "--------------------------------------------------------"
}

# --- MODE 2: AFTER UPGRADE (ANALYSIS) ---

analyze_post_upgrade() {
    print_header
    prepare_state_dir require
    STORED_VERSION=$(cat "$STATE_DIR/script_version" 2>/dev/null || echo "0.0")
    
    if [ "$STORED_VERSION" == "0.0" ]; then log_warn "$(translate "Capture from older script version. Data may be partial." "Capture ancienne version. Données partielles.")";
    elif [ "$STORED_VERSION" != "$VERSION" ]; then log_warn "$(translate "Version mismatch ($STORED_VERSION vs $VERSION)." "Décalage de version ($STORED_VERSION vs $VERSION).")";
    else log_info "$(translate "Post-upgrade analysis (versions in sync v$VERSION)." "Analyse post-mise à jour (Versions synchro v$VERSION).")"; fi

    # 1. OS & Kernel
    if [ -f "$STATE_DIR/prev_os_version" ]; then OLD_VER=$(cat "$STATE_DIR/prev_os_version"); else OLD_VER="N/A"; fi
    NEW_VER=$(get_debian_version)
    
    if [ -f "$STATE_DIR/prev_kernel" ]; then OLD_KERN=$(cat "$STATE_DIR/prev_kernel"); else OLD_KERN="N/A"; fi
    NEW_KERN=$(get_kernel)
    
    echo -e "\n${BOLD}[1] $(translate "SYSTEM" "SYSTÈME")${NC}"
    
    if [ "$OLD_VER" == "N/A" ]; then
        log_warn "$(translate "Previous OS version unknown. Current: $NEW_VER" "Version OS précédente inconnue. Actuelle : $NEW_VER")"
    elif [ "$OLD_VER" != "$NEW_VER" ]; then 
        log_success "$(translate "OS Updated : Debian $OLD_VER -> $NEW_VER" "OS mis à jour : Debian $OLD_VER -> $NEW_VER")"
    else 
        log_warn "$(translate "OS version unchanged ($NEW_VER)." "OS Version inchangée ($NEW_VER).")"
        update_score 5 "OS Same"
    fi

    if [ "$OLD_KERN" == "N/A" ]; then
        log_warn "$(translate "Previous kernel unknown. Current: $NEW_KERN" "Kernel précédent inconnu. Actuel : $NEW_KERN")"
    elif [ "$OLD_KERN" != "$NEW_KERN" ]; then 
        log_success "$(translate "Kernel Updated : $NEW_KERN (was $OLD_KERN)" "Kernel mis à jour : $NEW_KERN (précédent : $OLD_KERN)")"
    else 
        log_warn "$(translate "Kernel unchanged." "Kernel inchangé.")"
    fi

    # 2. Storage
    echo -e "\n${BOLD}[2] $(translate "STORAGE" "STOCKAGE")${NC}"
    get_mounts > "$STATE_DIR/curr_mounts"
    MISSING_MOUNTS=$(get_diff "$STATE_DIR/prev_mounts" "$STATE_DIR/curr_mounts")
    if [ ! -f "$STATE_DIR/prev_mounts" ]; then log_warn "$(translate "Missing mount data." "Données Mounts manquantes.")";
    elif [ -n "$MISSING_MOUNTS" ]; then 
        log_error "$(translate "Missing mount points:" "Points de montage disparus :")\n${RED}$MISSING_MOUNTS${NC}"; 
        update_score 20 "Missing Mounts";
    else log_success "$(translate "Mounts OK." "Montages OK.")"; fi
    
    # Use awk to avoid grep exiting 1 (pipefail) when no disks are above 90%
    DISK_FULL=$(df -h --output=pcent,target | awk 'NR>1 && $1+0 >= 90')
    if [ -n "$DISK_FULL" ]; then log_warn "$(translate "Disk >90%:" "Disque >90% :")\n${YELLOW}$DISK_FULL${NC}"; update_score 5 "Disk Full"; fi

    # 3. Core Services (INTELLIGENCE ADDED v2.4)
    echo -e "\n${BOLD}[3] $(translate "SERVICES & TIMERS" "SERVICES & TIMERS")${NC}"
    get_services > "$STATE_DIR/curr_services"
    MISSING_SERVICES=$(get_diff "$STATE_DIR/prev_services" "$STATE_DIR/curr_services")
    
    if [ -n "$MISSING_SERVICES" ]; then 
        missing_count=0
        smart_service_check "$MISSING_SERVICES" "$STATE_DIR/curr_services" || missing_count=$?
        
        if [ $missing_count -eq 0 ]; then
             log_success "$(translate "All missing services look like migrations." "Toutes les disparitions semblent être des migrations.")"
        else
             log_warn "$(translate "There are $missing_count services truly missing." "Il y a $missing_count services vraiment perdus.")"
             penalty=$((missing_count * 5))
             update_score $penalty "$missing_count Services Lost"
        fi
    else 
        log_success "$(translate "Services OK (No change)." "Services OK (Aucun changement).")"
    fi

    get_timers > "$STATE_DIR/curr_timers"
    MISSING_TIMERS=$(get_diff "$STATE_DIR/prev_timers" "$STATE_DIR/curr_timers")
    if [ -n "$MISSING_TIMERS" ]; then
        log_warn "$(translate "Timers missing:" "Timers disparus :")\n${YELLOW}$MISSING_TIMERS${NC}"
        update_score 2 "Timers Lost"
    else
        log_success "$(translate "Timers OK." "Timers OK.")"
    fi

    # 4. Web & PHP
    echo -e "\n${BOLD}[4] $(translate "WEB & PHP" "WEB & PHP")${NC}"
    check_web_health > "$STATE_DIR/curr_web_health"
    check_php_health > "$STATE_DIR/curr_php_health"
    if [ -f "$STATE_DIR/temp_php_modules" ]; then mv "$STATE_DIR/temp_php_modules" "$STATE_DIR/curr_php_modules"; fi

    PREV_HTTP=$(get_val "$STATE_DIR/prev_web_health" "HTTP_LOCALHOST_CODE" "NA")
    CURR_HTTP=$(get_val "$STATE_DIR/curr_web_health" "HTTP_LOCALHOST_CODE" "NA")
    if [ "$PREV_HTTP" == "NA" ]; then log_warn "$(translate "HTTP Code unknown." "Code HTTP inconnu.")"; elif [ "$PREV_HTTP" == "200" ] && [ "$CURR_HTTP" != "200" ]; then 
        log_error "$(translate "HTTP regression: $CURR_HTTP" "Régression HTTP : $CURR_HTTP")"; 
        update_score 15 "HTTP Regression";
    else log_success "$(translate "HTTP Status : $CURR_HTTP" "Statut HTTP : $CURR_HTTP")"; fi

    PREV_PHP_VER=$(get_val "$STATE_DIR/prev_php_health" "PHP_VERSION" "NONE")
    CURR_PHP_VER=$(get_val "$STATE_DIR/curr_php_health" "PHP_VERSION" "NONE")
    if [ "$PREV_PHP_VER" == "NONE" ]; then log_warn "$(translate "PHP version unknown." "Version PHP inconnue.")"; elif [ "$PREV_PHP_VER" != "$CURR_PHP_VER" ]; then
        log_warn "$(translate "PHP Changed : $PREV_PHP_VER -> $CURR_PHP_VER" "PHP modifié : $PREV_PHP_VER -> $CURR_PHP_VER")"
        MISSING_MODULES=$(get_diff "$STATE_DIR/prev_php_modules" "$STATE_DIR/curr_php_modules")
        if [ -n "$MISSING_MODULES" ]; then 
            log_error "$(translate "Missing PHP extensions:" "Extensions PHP perdues :")\n${RED}$MISSING_MODULES${NC}"; 
            update_score 5 "PHP Modules Lost";
        fi
    else log_success "$(translate "PHP Version : $CURR_PHP_VER" "Version PHP : $CURR_PHP_VER")"; fi

    echo -e "\n${BOLD}[4bis] $(translate "PACKAGES" "PAQUETS")${NC}"
    get_packages > "$STATE_DIR/curr_packages"
    dpkg-query -W -f '${Package}\t${Version}\n' | sort > "$STATE_DIR/curr_pkg_versions"
    report_package_changes

    # 5. Databases
    echo -e "\n${BOLD}[5] $(translate "DATABASES" "BASES DE DONNÉES")${NC}"
    check_db_health > "$STATE_DIR/curr_db_health"
    PREV_MYSQL=$(get_val "$STATE_DIR/prev_db_health" "MYSQL_PING" "NA")
    CURR_MYSQL=$(get_val "$STATE_DIR/curr_db_health" "MYSQL_PING" "NA")
    if [ "$PREV_MYSQL" == "OK" ] && [ "$CURR_MYSQL" != "OK" ]; then 
        log_error "$(translate "MariaDB/MySQL: PING FAIL!" "MariaDB/MySQL : PING FAIL !")"; 
        update_score 15 "DB Fail";
    else log_success "$(translate "DB Connectivity : OK" "Connectivité DB : OK")"; fi

    # 6. Firewall & Reseau
    echo -e "\n${BOLD}[6] $(translate "SECURITY & NETWORK" "SÉCURITÉ & RÉSEAU")${NC}"
    check_firewall > "$STATE_DIR/curr_firewall"
    PREV_NFT=$(get_val "$STATE_DIR/prev_firewall" "NFT_RULES_COUNT" "NA")
    CURR_NFT=$(get_val "$STATE_DIR/curr_firewall" "NFT_RULES_COUNT" "0")
    if [[ "$PREV_NFT" =~ ^[0-9]+$ ]] && [[ "$CURR_NFT" =~ ^[0-9]+$ ]]; then
        if [ "$CURR_NFT" -lt 5 ] && [ "$PREV_NFT" -gt 10 ]; then 
            log_error "$(translate "DANGER: NFTables wiped!" "DANGER : NFTables purgé !")"; 
            update_score 15 "Firewall Purged";
        else log_success "$(translate "Firewall rules : $CURR_NFT" "Règles firewall : $CURR_NFT")"; fi
    fi

    get_ports > "$STATE_DIR/curr_ports"
    
    if [ ! -s "$STATE_DIR/prev_ports" ]; then
        log_warn "$(translate "Previous ports data is empty or missing." "Données de ports précédentes vides ou manquantes.")"
    fi

    MISSING_PORTS=$(get_diff "$STATE_DIR/prev_ports" "$STATE_DIR/curr_ports")
    if [ -n "$MISSING_PORTS" ]; then 
        log_warn "$(translate "Ports closed:" "Ports fermés :")\n${YELLOW}$MISSING_PORTS${NC}"; 
        update_score 2 "Ports Closed";
    else log_success "$(translate "Ports OK." "Ports OK.")"; fi

    # 7. Maintenance & Cleanup (NEW v2.5)
    echo -e "\n${BOLD}[7] $(translate "CLEANUP & MAINTENANCE" "NETTOYAGE & MAINTENANCE")${NC}"
    check_cleanup

    # 8. Config Drifts
    echo -e "\n${BOLD}[8] $(translate "CONFLICTS (/etc)" "CONFLITS (/etc)")${NC}"
    CONFIG_DRIFT=$(find /etc -name "*.dpkg-*" -o -name "*.ucf-*" 2>/dev/null)
    if [ -n "$CONFIG_DRIFT" ]; then 
        drift_count=$(echo "$CONFIG_DRIFT" | wc -l)
        log_error "$(translate "$drift_count conflicts detected." "$drift_count Conflits détectés.")";
        penalty=$((drift_count * 2))
        update_score $penalty "Config Files"

        echo -e "${RED}$CONFIG_DRIFT${NC}"
        echo -e "\n${BOLD}$(translate "Launch the conflict resolution tool?" "Voulez-vous lancer l'outil de résolution de conflits ?")${NC}"
        if read -e -p "$(translate "Resolve? (y/N) : " "Résoudre ? (o/N) : ")" choice < /dev/tty; then
             choice=${choice,,}
             if [[ $choice =~ ^(o|y) ]]; then resolve_conflicts "$CONFIG_DRIFT"; else echo "$(translate "Skipped." "Ignoré.")"; fi
        fi
    else log_success "$(translate "No configuration conflicts." "Aucun conflit de configuration.")"; fi

    display_score
    write_json_report "$JSON_REPORT"
    
    # Keep history, optional cleanup
    if [ "$DRY_RUN" -eq 1 ]; then
        log_warn "$(translate "Dry-run mode: state snapshots preserved for review." "Mode simulation : instantanés conservés pour analyse.")"
        echo -e "$(translate "Report generated without altering baseline." "Rapport généré sans modifier la baseline.")"
    elif [ "$CLEANUP" -eq 1 ]; then
        rm -f "$STATE_DIR"/prev_* "$STATE_DIR"/curr_* "$STATE_DIR"/temp_* "$STATE_DIR"/script_version
        echo -e "$(translate "Done. Report saved to $STATE_DIR/history.log" "Terminé. Rapport sauvegardé dans $STATE_DIR/history.log")"
    else
        log_warn "$(translate "Snapshots preserved (use --cleanup to remove them)." "Instantanés conservés (utilisez --cleanup pour les supprimer).")"
        echo -e "$(translate "Report saved; no files deleted." "Rapport sauvegardé ; aucun fichier supprimé.")"
    fi
    echo "--------------------------------------------------------"
}

# --- MAIN ---

if [ ! -d "$STATE_DIR" ]; then
    collect_pre_upgrade
else
    analyze_post_upgrade
fi
