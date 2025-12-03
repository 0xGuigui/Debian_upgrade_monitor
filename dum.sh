#!/bin/bash

# ==============================================================================
# DEBIAN UPGRADE MONITOR v2.8
# Written by 0xGuigui
# ==============================================================================
# System state monitoring script for pre/post upgrade.
# Usage: sudo ./upgrade_monitor.sh
# ==============================================================================

set -u

# --- CONFIGURATION ---
VERSION="2.8"
STATE_DIR="/var/lib/debian-upgrade-monitor"

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

detect_ui_language

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

# Root Verification
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[$(translate "ERROR" "ERREUR")] $(translate "This script must be run as root." "Ce script doit être exécuté avec les privilèges root.")${NC}"
  exit 1
fi

# --- SCORE FUNCTIONS ---

update_score() {
    local penalty=$1
    local reason=$2
    ((SCORE-=penalty))
    if [ $SCORE -lt 0 ]; then SCORE=0; fi
}

display_score() {
    echo -e "\n======================================================"
    echo -e "   $(translate "SYSTEM AUDIT RESULT" "RÉSULTAT DE L'AUDIT SYSTÈME")"
    echo -e "======================================================"
    
    local color=$GREEN
    local status
    status=$(translate "EXCELLENT" "EXCELLENT")

    if [ $SCORE -lt 90 ]; then color=$YELLOW; status=$(translate "WARNING" "ATTENTION"); fi
    if [ $SCORE -lt 70 ]; then color=$RED; status=$(translate "CRITICAL" "CRITIQUE"); fi

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
    if [ -d "$STATE_DIR" ]; then
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
        if [[ "$old_svc" =~ php.*fpm ]]; then candidate=$(echo "$current_services_content" | grep -E "php.*fpm" | head -n 1); fi
        if [[ "$old_svc" =~ postgresql ]]; then candidate=$(echo "$current_services_content" | grep -E "postgresql" | head -n 1); fi

        # HEURISTIC 3: Fuzzy Match & Alias
        if [ -z "$candidate" ]; then
            candidate=$(echo "$current_services_content" | grep -i "$stem" | head -n 1)
            if [ -z "$candidate" ] && [[ "$stem" == *"phpfpm"* ]]; then candidate=$(echo "$current_services_content" | grep "php" | grep "fpm" | head -n 1); fi
            
            if [ -z "$candidate" ]; then
                case "$stem" in
                    "mysql") candidate=$(echo "$current_services_content" | grep "mariadb" | head -n 1) ;;
                    "mariadb") candidate=$(echo "$current_services_content" | grep "mysql" | head -n 1) ;;
                    "cron") candidate=$(echo "$current_services_content" | grep "systemd-cron" | head -n 1) ;;
                    "ntp") candidate=$(echo "$current_services_content" | grep "systemd-timesyncd" | head -n 1) ;;
                esac
            fi
        fi

        if [ -n "$candidate" ]; then
            echo -e "   -> ${CYAN}[MIGRATED]${NC} $old_svc $(translate "seems to be replaced by" "semble être devenu") ${GREEN}$candidate${NC}"
        else
            echo -e "   -> ${RED}[MISSING]  $old_svc${NC} $(translate "(No equivalent found)" "(Aucun équivalent trouvé)")"
            ((truly_missing_count++))
        fi

    done <<< "$missing_list"

    return $truly_missing_count
}

# --- CONFLICT RESOLVER ---

resolve_conflicts() {
    local conflicts="$1"
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
                d) if command -v colordiff >/dev/null 2>&1; then colordiff -u "$real_file" "$conflict_file" | less -R; else diff -u --color=auto "$real_file" "$conflict_file" | less -R; fi ;;
                k) rm "$conflict_file"; log_success "$(translate "Cleaned." "Nettoyé.")"; break ;;
                r) cp "$real_file" "$real_file.bak"; mv "$conflict_file" "$real_file"; log_success "$(translate "Updated." "Mis à jour.")"; break ;;
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
    local autoremove_count=$(apt-get -s autoremove | grep "^Remv" | wc -l)
    
    if [ "$autoremove_count" -gt 0 ]; then
        log_clean "$(translate "$autoremove_count unused packages detected (orphan dependencies)." "$autoremove_count paquets inutiles détectés (dépendances orphelines).")"
        echo -e "   -> ${CYAN}$(translate "Tip: consider a backup first (e.g. apt-clone)." "Conseil : Pensez à faire un backup avant (ex: apt-clone).")${NC}"
        echo -e "   -> $(translate "Suggested command" "Commande suggérée") : ${BOLD}apt autoremove --purge${NC}"
        update_score 2 "Need Autoremove"
        ((issues++))
    else
        log_success "$(translate "No unused packages (Autoremove clean)." "Aucun paquet inutile (Autoremove propre).")"
    fi

    # 2. RC Packages (Residual Config)
    # These are packages that have been removed but their config files remain
    local rc_count=$(dpkg -l | grep "^rc" | wc -l)
    
    if [ "$rc_count" -gt 0 ]; then
        log_clean "$(translate "$rc_count 'ghost packages' (RC - Residual Config) detected." "$rc_count 'paquets fantômes' (RC - Residual Config) détectés.")"
        echo -e "   -> $(translate "Suggested command" "Commande suggérée") : ${BOLD}apt purge \$(dpkg -l | grep '^rc' | awk '{print \$2}')${NC}"
        update_score 1 "RC Packages"
        ((issues++))
    else
        log_success "$(translate "No configuration residues (RC clean)." "Aucun résidu de configuration (RC propre).")"
    fi

    # 3. Old Kernels
    # Count installed linux images
    local kernel_count=$(dpkg -l | grep "linux-image-[0-9]" | grep "^ii" | wc -l)
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
    log_info "$(translate "No existing baseline. Starting pre-upgrade capture." "État initial inexistant. Démarrage de la capture pré-mise à jour.")"
    echo "$(translate "Storage directory" "Répertoire de stockage") : $STATE_DIR"
    if ! mkdir -p "$STATE_DIR"; then log_error "$(translate "Failed to create" "Erreur création") $STATE_DIR"; exit 1; fi
    chmod 700 "$STATE_DIR"
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
    
    DISK_FULL=$(df -h --output=pcent,target | grep -E '(100%|9[0-9]%)')
    if [ -n "$DISK_FULL" ]; then log_warn "$(translate "Disk >90%:" "Disque >90% :")\n${YELLOW}$DISK_FULL${NC}"; update_score 5 "Disk Full"; fi

    # 3. Core Services (INTELLIGENCE ADDED v2.4)
    echo -e "\n${BOLD}[3] $(translate "SERVICES & TIMERS" "SERVICES & TIMERS")${NC}"
    get_services > "$STATE_DIR/curr_services"
    MISSING_SERVICES=$(get_diff "$STATE_DIR/prev_services" "$STATE_DIR/curr_services")
    
    if [ -n "$MISSING_SERVICES" ]; then 
        smart_service_check "$MISSING_SERVICES" "$STATE_DIR/curr_services"
        missing_count=$?
        
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
    
    # Keep history, clean up the rest
    rm -f "$STATE_DIR"/prev_* "$STATE_DIR"/curr_* "$STATE_DIR"/temp_* "$STATE_DIR"/script_version
    echo -e "$(translate "Done. Report saved to $STATE_DIR/history.log" "Terminé. Rapport sauvegardé dans $STATE_DIR/history.log")"
    echo "--------------------------------------------------------"
}

# --- MAIN ---

if [ ! -d "$STATE_DIR" ]; then
    collect_pre_upgrade
else
    analyze_post_upgrade
fi
