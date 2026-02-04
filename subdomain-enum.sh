#!/bin/bash
###########################################
# Ultimate Subdomain Enumerator with Depth Discovery
# Usage:
#   subenum -l domains.txt -o allsubs.txt --depth
#   subenum -d domain.com  -o allsubs.txt --depth
#   subenum -l domains.txt -o allsubs.txt --resolve-only
# Author: Lucas - Bug Bounty Edition
###########################################

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
BLUE='\033[1;34m'; CYAN='\033[1;36m'; PURPLE='\033[1;35m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVERS="${SCRIPT_DIR}/resolvers.txt"
DEPTH_JOBS=15

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
has_tool()    { command -v "$1" &>/dev/null; }

banner() {
    clear
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║      SUBENUM v2 - Advanced Subdomain Enumerator       ║"
    echo "║      Phase 1: Full Enum → puredns                     ║"
    echo "║      Phase 2: Depth Loop + Permutations (optional)    ║"
    echo "║      Author: Lucas                                    ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "${RED}SubEnum v2${NC}"
    echo ""
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 -l domains.txt -o allsubs.txt"
    echo "  $0 -d domain.com  -o allsubs.txt --depth"
    echo "  $0 -l domains.txt -o allsubs.txt --resolve-only"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo "  -l FILE          File with one domain per line"
    echo "  -d DOMAIN        Single domain to enumerate"
    echo "  -o FILE          Output file (default: subs.txt)"
    echo "  --depth          Enable depth discovery (recursive + permutations)"
    echo "  --resolve-only   Skip enumeration, only resolve existing file"
    echo "  --no-resolve     Skip puredns resolution"
    echo "  -h, --help       Show this help"
    echo ""
    echo -e "${CYAN}Pipeline:${NC}"
    echo "  Phase 1: enum (all sources) → puredns → output"
    echo "  Phase 2: depth (passive + active + permutations) → loop until dry"
    exit 1
}

###########################################
# Resolvers
###########################################
download_resolvers() {
    local need=false
    if [[ ! -f "$RESOLVERS" ]]; then
        need=true
    else
        local age=$(( $(date +%s) - $(stat -c %Y "$RESOLVERS" 2>/dev/null || echo 0) ))
        [[ $age -gt 86400 ]] && need=true
    fi
    if [[ "$need" == true ]]; then
        log_info "Downloading resolvers..."
        curl -s --max-time 15 "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt" -o "${RESOLVERS}.tmp"
        if [[ -s "${RESOLVERS}.tmp" ]]; then
            mv "${RESOLVERS}.tmp" "$RESOLVERS"
            log_success "Resolvers: $(wc -l < "$RESOLVERS" | tr -d ' ')"
        else
            rm -f "${RESOLVERS}.tmp"
            log_warn "Resolver download failed"
        fi
    fi
}

check_requirements() {
    has_tool curl || { log_error "curl required"; exit 1; }
    echo -e "${CYAN}Tools Status:${NC}"
    for t in subfinder assetfinder findomain amass puredns waybackurls; do
        has_tool $t && echo -e "  ${GREEN}✓${NC} $t" || echo -e "  ${YELLOW}✗${NC} $t"
    done
    echo ""
}

live_count() {
    local label="$1" dir="$2" domain="$3"
    while jobs -r | grep -q .; do
        local n
        n=$(cat "$dir"/*.txt 2>/dev/null | wc -l)
        echo -ne "\r${BLUE}[INFO]${NC} [$domain] ${label}... ${CYAN}${n}${NC}"
        sleep 1
    done
    echo ""
}

###########################################
# Phase 1: Full Enumeration
###########################################
enumerate_domain() {
    local domain=$1
    local tmp_dir=$2
    local d="$tmp_dir/enum_$domain"
    mkdir -p "$d"

    echo -e "${YELLOW}───────────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}  ${domain}${NC}"
    echo -e "${YELLOW}───────────────────────────────────────────────────────${NC}"

    # Passive sources
    curl -s --max-time 30 "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/crtsh.txt" &
    curl -s --max-time 30 "https://rapiddns.io/subdomain/$domain?full=1" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/rapiddns.txt" &
    curl -s --max-time 60 "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | sed -e 's_https*://__' -e "s/\/.*//" | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/webarchive.txt" &
    curl -s --max-time 30 "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/alienvault.txt" &
    curl -s --max-time 30 "https://api.hackertarget.com/hostsearch/?q=$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/hackertarget.txt" &
    curl -s --max-time 30 "https://urlscan.io/api/v1/search/?q=domain:$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/urlscan.txt" &
    curl -s --max-time 30 "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/threatcrowd.txt" &
    curl -s --max-time 30 "https://jldc.me/anubis/subdomains/$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/anubis.txt" &
    curl -s --max-time 30 "https://dns.bufferover.run/dns?q=.$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/bufferover.txt" &
    curl -s --max-time 30 "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/certspotter.txt" &
    has_tool waybackurls && echo "$domain" | waybackurls 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$d/wayback.txt" &

    live_count "Passive" "$d" "$domain"

    # Active tools
    has_tool subfinder   && subfinder   -d "$domain" -silent -all 2>/dev/null > "$d/subfinder.txt"   &
    has_tool assetfinder && assetfinder -subs-only "$domain" 2>/dev/null | sed 's/\*\.//g' > "$d/assetfinder.txt" &
    has_tool findomain   && findomain   -t "$domain" -q 2>/dev/null > "$d/findomain.txt"   &
    has_tool amass       && timeout 120 amass enum -passive -d "$domain" 2>/dev/null > "$d/amass.txt" &

    live_count "Active" "$d" "$domain"

    # Merge
    echo "$domain" > "$d/main.txt"
    cat "$d"/*.txt 2>/dev/null \
        | grep -oE "[a-zA-Z0-9._-]+\.$domain" \
        | sed 's/^\*\.//g;s/^\.//g' \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u | grep -v "^$" > "$d/all.txt"

    local total
    total=$(wc -l < "$d/all.txt" | tr -d ' ')
    log_success "[$domain] Enumerated: ${total}"

    echo "$d/all.txt"
}

resolve_domains() {
    local input="$1"
    local output="$2"
    
    if ! has_tool puredns || [[ ! -f "$RESOLVERS" ]]; then
        log_warn "puredns or resolvers not available, skipping resolution"
        cp "$input" "$output"
        return
    fi

    local total
    total=$(wc -l < "$input" | tr -d ' ')
    log_info "Resolving ${total} subdomains..."
    
    puredns resolve "$input" -r "$RESOLVERS" -w "${output}.tmp" > /dev/null 2>&1
    
    if [[ -s "${output}.tmp" ]]; then
        local resolved
        resolved=$(wc -l < "${output}.tmp" | tr -d ' ')
        mv "${output}.tmp" "$output"
        log_success "Live: ${resolved} | Dead: $((total - resolved))"
    else
        rm -f "${output}.tmp"
        log_warn "No live subdomains found"
        touch "$output"
    fi
}

###########################################
# Phase 2: Depth Discovery
###########################################
generate_permutations() {
    local input="$1"
    local output="$2"
    
    log_info "Generating permutations..."
    > "$output"
    
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        
        # Prefixes
        for p in dev staging test stage api app admin portal www1 www2 mail vpn ftp beta prod production internal old new mobile m uat demo cdn assets static media images img js css api-v1 api-v2 dashboard panel; do
            echo "${p}.${sub}" >> "$output"
            echo "${p}-${sub}" >> "$output"
        done
        
        # Suffixes
        for s in dev staging test api old new backup beta 01 02 03 1 2 3 prod uat demo; do
            echo "${sub}-${s}" >> "$output"
        done
        
        # Numbers
        for n in 1 2 3 01 02 03; do
            echo "${sub}${n}" >> "$output"
            echo "${sub}-${n}" >> "$output"
        done
    done < "$input"
    
    local count
    count=$(sort -u "$output" -o "$output"; wc -l < "$output" | tr -d ' ')
    log_success "Generated ${count} permutations"
}

depth_discovery() {
    local input="$1"
    local known="$2"
    local tmp_dir="$3"
    local iteration=0

    while true; do
        iteration=$((iteration+1))
        local total
        total=$(wc -l < "$input" | tr -d ' ')
        [[ $total -eq 0 ]] && break

        echo ""
        echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
        echo -e "${PURPLE}  DEPTH ${iteration} — ${total} subdomains${NC}"
        echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"

        local d="$tmp_dir/depth_${iteration}"
        mkdir -p "$d"
        > "$d/raw.txt"

        local count=0
        # Enumerate each live subdomain
        while IFS= read -r sub; do
            [[ -z "$sub" ]] && continue
            count=$((count+1))

            {
                # Passive sources
                curl -s --max-time 20 "https://crt.sh/?q=%25.${sub}&output=json" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${sub}"
                curl -s --max-time 20 "https://rapiddns.io/subdomain/${sub}?full=1" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${sub}"
                curl -s --max-time 20 "https://api.certspotter.com/v1/issuances?domain=${sub}&include_subdomains=true&expand=dns_names" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${sub}"
                curl -s --max-time 20 "https://otx.alienvault.com/api/v1/indicators/domain/${sub}/passive_dns" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${sub}"
                curl -s --max-time 20 "https://dns.bufferover.run/dns?q=.${sub}" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${sub}"
                has_tool waybackurls && echo "$sub" | waybackurls 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${sub}"
                
                # Active tools (without subfinder to save API credits)
                has_tool assetfinder && assetfinder -subs-only "$sub" 2>/dev/null | sed 's/\*\.//g'
                has_tool findomain   && findomain   -t "$sub" -q 2>/dev/null
            } >> "$d/raw.txt" &

            # Throttle
            while [[ $(jobs -r | wc -l) -ge $DEPTH_JOBS ]]; do
                local new
                new=$(sed 's/^\*\.//g;s/^\.//g' "$d/raw.txt" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u | comm -23 - <(sort "$known") 2>/dev/null | wc -l)
                echo -ne "\r${PURPLE}[DEPTH ${iteration}]${NC} ${count}/${total} | raw: ${CYAN}${new}${NC}"
                sleep 1
            done
        done < "$input"

        wait
        echo ""

        # Generate permutations
        generate_permutations "$input" "$d/perms.txt"
        cat "$d/perms.txt" >> "$d/raw.txt"

        # Clean and filter
        sed 's/^\*\.//g;s/^\.//g' "$d/raw.txt" | tr '[:upper:]' '[:lower:]' | sort -u | grep -v "^$" > "$d/clean.txt"
        comm -23 "$d/clean.txt" <(sort "$known") > "$d/new.txt"

        local new_count
        new_count=$(wc -l < "$d/new.txt" | tr -d ' ')
        if [[ $new_count -eq 0 ]]; then
            log_info "No new subdomains found. Depth discovery complete."
            break
        fi
        log_success "New subdomains: ${new_count}"

        # Resolve
        local live="$d/live.txt"
        if has_tool puredns && [[ -f "$RESOLVERS" ]]; then
            log_info "Resolving..."
            puredns resolve "$d/new.txt" -r "$RESOLVERS" -w "$live" > /dev/null 2>&1
            if [[ ! -s "$live" ]]; then
                log_warn "No live subdomains found. Depth complete."
                break
            fi
            local live_count
            live_count=$(wc -l < "$live" | tr -d ' ')
            log_success "Live: ${live_count} | Dead: $((new_count - live_count))"
        else
            cp "$d/new.txt" "$live"
        fi

        local live_count
        live_count=$(wc -l < "$live" | tr -d ' ')
        [[ $live_count -eq 0 ]] && break

        # Update known list
        cat "$live" >> "$known"
        sort -u "$known" -o "$known"

        # Use live subs as input for next iteration
        input="$live"
    done

    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}  DEPTH DISCOVERY COMPLETE${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
}

###########################################
# Main
###########################################
main() {
    local list_file="" single_domain="" output="subs.txt"
    local enable_depth=false resolve_only=false no_resolve=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l) list_file="$2"; shift 2 ;;
            -d) single_domain="$2"; shift 2 ;;
            -o) output="$2"; shift 2 ;;
            --depth) enable_depth=true; shift ;;
            --resolve-only) resolve_only=true; shift ;;
            --no-resolve) no_resolve=true; shift ;;
            -h|--help) usage ;;
            *) log_error "Unknown option: $1"; usage ;;
        esac
    done

    # Build domain list
    declare -a DOMAINS=()
    if [[ -n "$list_file" ]]; then
        [[ ! -f "$list_file" ]] && { log_error "File not found: $list_file"; exit 1; }
        while IFS= read -r line; do
            line=$(echo "$line" | sed 's/#.*//' | xargs)
            [[ -n "$line" ]] && DOMAINS+=("$line")
        done < "$list_file"
    fi
    [[ -n "$single_domain" ]] && {
        single_domain="${single_domain#https://}"; single_domain="${single_domain#http://}"; single_domain="${single_domain%/}"
        DOMAINS+=("$single_domain")
    }

    # Resolve-only mode
    if [[ "$resolve_only" == true ]]; then
        [[ ! -f "$output" ]] && { log_error "File not found: $output"; exit 1; }
        banner
        check_requirements
        download_resolvers
        echo ""
        log_info "Resolve-only mode"
        resolve_domains "$output" "${output}.resolved"
        mv "${output}.resolved" "$output"
        local final
        final=$(wc -l < "$output" | tr -d ' ')
        log_success "Final: ${final} live subdomains in ${output}"
        exit 0
    fi

    [[ ${#DOMAINS[@]} -eq 0 ]] && { log_error "No domains specified!"; usage; }

    TMP_DIR="/tmp/subenum_$$"
    mkdir -p "$TMP_DIR"
    trap "rm -rf $TMP_DIR" EXIT

    KNOWN="$TMP_DIR/known.txt"
    ALL_SUBS="$TMP_DIR/all.txt"
    LIVE_ALL="$TMP_DIR/live_all.txt"
    > "$KNOWN"; > "$ALL_SUBS"; > "$LIVE_ALL"

    banner
    echo -e "${CYAN}Targets:${NC} ${#DOMAINS[@]} domain(s)"
    for d in "${DOMAINS[@]}"; do echo -e "  ${CYAN}→${NC} $d"; done
    echo -e "${CYAN}Output:${NC}  $output"
    echo -e "${CYAN}Depth:${NC}   $(${enable_depth} && echo 'Enabled' || echo 'Disabled')"
    echo ""

    check_requirements
    download_resolvers
    echo ""

    START_TIME=$(date +%s)

    # PHASE 1: Full Enumeration
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  PHASE 1 — Full Enumeration${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""

    for dom in "${DOMAINS[@]}"; do
        dom="${dom#https://}"; dom="${dom#http://}"; dom="${dom%/}"
        local result_file
        result_file=$(enumerate_domain "$dom" "$TMP_DIR")
        cat "$result_file" >> "$ALL_SUBS"
    done

    # Merge and deduplicate
    sort -u "$ALL_SUBS" -o "$ALL_SUBS"
    local enum_total
    enum_total=$(wc -l < "$ALL_SUBS" | tr -d ' ')

    echo ""
    log_info "Total enumerated: ${enum_total}"

    # Resolve
    if [[ "$no_resolve" == false ]]; then
        resolve_domains "$ALL_SUBS" "$LIVE_ALL"
    else
        cp "$ALL_SUBS" "$LIVE_ALL"
    fi

    cp "$LIVE_ALL" "$KNOWN"
    cp "$LIVE_ALL" "$output"

    local phase1_total
    phase1_total=$(wc -l < "$output" | tr -d ' ')

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  PHASE 1 COMPLETE${NC}"
    echo -e "${GREEN}  Total: ${phase1_total} subdomains${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"

    # PHASE 2: Depth Discovery
    if [[ "$enable_depth" == true ]]; then
        local live_count
        live_count=$(wc -l < "$LIVE_ALL" | tr -d ' ')
        
        if [[ $live_count -eq 0 ]]; then
            log_warn "No live subdomains for depth discovery"
        else
            echo ""
            echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
            echo -e "${PURPLE}  PHASE 2 — Depth Discovery${NC}"
            echo -e "${PURPLE}  Input: ${live_count} live subdomains${NC}"
            echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"

            depth_discovery "$LIVE_ALL" "$KNOWN" "$TMP_DIR"

            # Update output with all discovered subdomains
            sort -u "$KNOWN" -o "$output"
        fi
    fi

    # Final stats
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    local final_total
    final_total=$(wc -l < "$output" | tr -d ' ')

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  DISCOVERY COMPLETE${NC}"
    echo -e "${GREEN}  Phase 1: ${phase1_total} subdomains${NC}"
    if [[ "$enable_depth" == true ]]; then
        echo -e "${GREEN}  Phase 2: +$((final_total - phase1_total)) subdomains${NC}"
    fi
    echo -e "${GREEN}  Final:   ${final_total} total subdomains${NC}"
    echo -e "${GREEN}  Output:  ${output}${NC}"
    echo -e "${GREEN}  Time:    ${ELAPSED}s${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
}

main "$@"
