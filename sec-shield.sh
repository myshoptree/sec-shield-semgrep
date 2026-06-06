#!/usr/bin/env bash
set -uo pipefail

# ╔══════════════════════════════════════════════════════════════╗
# ║  sec-shield — security scanner CLI                          ║
# ║  Usage: curl -fsSL <raw-url>/sec-shield.sh | bash -s [path]║
# ╚══════════════════════════════════════════════════════════════╝

RULES_REPO="https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/rules"
RULES_MANIFEST="https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/rules/manifest.txt"
VERSION="1.1.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TARGET="${1:-.}"
SECRETS_COUNT=0
SEMGREP_CUSTOM_COUNT=0
SEMGREP_COMMUNITY_COUNT=0
OSV_COUNT=0
RULES_DOWNLOADED=0
RULES_DIR=""

cleanup() {
  [ -n "$RULES_DIR" ] && rm -rf "$RULES_DIR"
}
trap cleanup EXIT INT TERM

# ─── Banner ───────────────────────────────────────────────────

banner() {
  echo ""
  echo -e "${CYAN}┌──────────────────────────────────────────────┐${NC}"
  echo -e "${CYAN}│  ${BOLD}sec-shield${NC}${CYAN}  security scanner  ${DIM}v${VERSION}${NC}${CYAN}          │${NC}"
  echo -e "${CYAN}└──────────────────────────────────────────────┘${NC}"
  echo ""
  echo -e "  ${DIM}Target:  $(cd "$TARGET" 2>/dev/null && pwd || echo "$TARGET")${NC}"
  echo -e "  ${DIM}Fecha:   $(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo -e "  ${DIM}Sistema: $(uname -s) $(uname -m)${NC}"
  echo ""
}

# ─── Dependency check (no auto-install) ──────────────────────

check_deps() {
  echo -e "${BOLD}═══ Herramientas ═══${NC}"
  echo ""

  local missing=()
  local outdated=()
  local os_type=$(uname -s)

  # Build curl auth header for GitHub API (avoid rate-limits)
  local gh_auth=()
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    gh_auth=(-H "Authorization: token ${GITHUB_TOKEN}")
  fi

  # Check python3
  if command -v python3 &>/dev/null; then
    local py_version=$(python3 --version 2>/dev/null | awk '{print $2}')
    echo -e "  ${GREEN}✓${NC} python3  ${DIM}v${py_version}${NC}"
  else
    echo -e "  ${RED}✗${NC} python3  ${DIM}(no instalado)${NC}"
    missing+=("python3")
  fi

  # Check osv-scanner (optional)
  if command -v osv-scanner &>/dev/null; then
    local osv_version=$(osv-scanner --version 2>/dev/null | awk '{print $NF}' || echo "?")
    local osv_latest=$(curl -sSf "${gh_auth[@]+"${gh_auth[@]}"}" "https://api.github.com/repos/google/osv-scanner/releases/latest" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null || echo "")

    if [ -n "$osv_latest" ] && [ "$osv_version" != "$osv_latest" ]; then
      echo -e "  ${YELLOW}⬆${NC} osv-scanner ${DIM}v${osv_version}${NC} → ${GREEN}v${osv_latest} disponible${NC}"
      outdated+=("osv-scanner")
    else
      echo -e "  ${GREEN}✓${NC} osv-scanner ${DIM}v${osv_version} (última)${NC}"
    fi
  else
    echo -e "  ${YELLOW}○${NC} osv-scanner ${DIM}(no instalado, escaneo de dependencias deshabilitado)${NC}"
  fi

  # Check semgrep
  if command -v semgrep &>/dev/null; then
    local sg_version=$(semgrep --version 2>/dev/null || echo "?")
    local sg_latest=$(curl -sSf "${gh_auth[@]+"${gh_auth[@]}"}" "https://api.github.com/repos/semgrep/semgrep/releases/latest" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null || echo "")

    if [ -n "$sg_latest" ] && [ "$sg_version" != "$sg_latest" ]; then
      echo -e "  ${YELLOW}⬆${NC} semgrep  ${DIM}v${sg_version}${NC} → ${GREEN}v${sg_latest} disponible${NC}"
      outdated+=("semgrep")
    else
      echo -e "  ${GREEN}✓${NC} semgrep  ${DIM}v${sg_version} (última)${NC}"
    fi
  else
    echo -e "  ${RED}✗${NC} semgrep  ${DIM}(no instalado)${NC}"
    missing+=("semgrep")
  fi

  # Check gitleaks
  if command -v gitleaks &>/dev/null; then
    local gl_version=$(gitleaks version 2>/dev/null || echo "?")
    local gl_latest=$(curl -sSf "${gh_auth[@]+"${gh_auth[@]}"}" "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null || echo "")

    if [ -n "$gl_latest" ] && [ "$gl_version" != "$gl_latest" ]; then
      echo -e "  ${YELLOW}⬆${NC} gitleaks ${DIM}v${gl_version}${NC} → ${GREEN}v${gl_latest} disponible${NC}"
      outdated+=("gitleaks")
    else
      echo -e "  ${GREEN}✓${NC} gitleaks ${DIM}v${gl_version} (última)${NC}"
    fi
  else
    echo -e "  ${RED}✗${NC} gitleaks ${DIM}(no instalado)${NC}"
    missing+=("gitleaks")
  fi

  echo ""

  # Suggest osv-scanner install if missing
  if ! command -v osv-scanner &>/dev/null; then
    if [ "$os_type" = "Darwin" ]; then
      echo -e "  ${DIM}Opcional: brew install osv-scanner (escaneo de dependencias)${NC}"
    else
      echo -e "  ${DIM}Opcional: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest${NC}"
    fi
    echo ""
  fi

  # Show update commands if outdated
  if [ ${#outdated[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Actualizar:${NC}"
    if [ "$os_type" = "Darwin" ]; then
      echo -e "    brew upgrade ${outdated[*]}"
    else
      for dep in "${outdated[@]}"; do
        case "$dep" in
          semgrep) echo -e "    pip3 install --upgrade semgrep" ;;
          gitleaks) echo -e "    go install github.com/zricethezav/gitleaks/v8@latest" ;;
          osv-scanner) echo -e "    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest" ;;
        esac
      done
    fi
    echo ""
    echo -e "  ${DIM}Continuando con versiones actuales...${NC}"
    echo ""
  fi

  # Abort if missing
  if [ ${#missing[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Para continuar necesitas instalar: ${BOLD}${missing[*]}${NC}"
    echo ""

    if [ "$os_type" = "Darwin" ]; then
      echo -e "  ${CYAN}macOS (brew):${NC}"
      echo -e "    brew install ${missing[*]}"
      echo ""
    elif [ "$os_type" = "Linux" ]; then
      echo -e "  ${CYAN}Linux:${NC}"
      for dep in "${missing[@]}"; do
        case "$dep" in
          python3)
            echo -e "    sudo apt-get install python3"
            echo -e "    ${DIM}# o: sudo dnf install python3${NC}"
            ;;
          semgrep)
            echo -e "    pip3 install semgrep"
            echo -e "    ${DIM}# o: pipx install semgrep${NC}"
            ;;
          gitleaks)
            echo -e "    # descargar desde: https://github.com/gitleaks/gitleaks/releases"
            echo -e "    ${DIM}# o con go: go install github.com/zricethezav/gitleaks/v8@latest${NC}"
            ;;
        esac
      done
      echo ""
    fi

    echo -e "  ${DIM}Luego volvé a ejecutar este comando.${NC}"
    echo ""
    exit 1
  fi
}

# ─── Rules download ──────────────────────────────────────────

check_rules() {
  echo -e "${BOLD}═══ Reglas de seguridad ═══${NC}"
  echo ""

  RULES_DIR=$(mktemp -d)

  # Try dynamic manifest first, fallback to hardcoded list
  local rule_files=()
  local manifest
  manifest=$(curl -sSfL "$RULES_MANIFEST" 2>/dev/null || echo "")

  if [ -n "$manifest" ]; then
    while IFS= read -r rule; do
      [ -n "$rule" ] && rule_files+=("$rule")
    done <<< "$manifest"
  fi

  if [ ${#rule_files[@]} -eq 0 ]; then
    rule_files=("mongoose-nosql-injection" "js-sqli" "axios-resource-injection" "exec-injection" "jwt-misconfig" "insecure-cookie" "ai-agent-hook-injection" "supply-chain-payload" "malicious-instructions")
  fi

  local total=${#rule_files[@]}

  for rule in "${rule_files[@]}"; do
    if curl -sSfL "${RULES_REPO}/${rule}.yml" -o "${RULES_DIR}/${rule}.yml" 2>/dev/null; then
      echo -e "  ${GREEN}✓${NC} ${rule}"
    else
      echo -e "  ${YELLOW}○${NC} ${rule} ${DIM}(no disponible remotamente)${NC}"
      rm -f "${RULES_DIR}/${rule}.yml"
    fi
  done

  RULES_DOWNLOADED=$(find "$RULES_DIR" -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')

  # Validate rules actually parse correctly
  local valid_rules=0
  if [ "$RULES_DOWNLOADED" -gt 0 ]; then
    local validate_output
    validate_output=$(semgrep scan --config="$RULES_DIR" --validate 2>&1) || true
    valid_rules=$(echo "$validate_output" | grep -o "[0-9]* valid" | grep -o "[0-9]*" || echo "0")
    valid_rules=$((valid_rules + 0))

    local invalid_rules
    invalid_rules=$(echo "$validate_output" | grep -o "[0-9]* invalid" | grep -o "[0-9]*" || echo "0")
    invalid_rules=$((invalid_rules + 0))

    if [ "$invalid_rules" -gt 0 ]; then
      echo ""
      echo -e "  ${RED}⚠ ${invalid_rules} regla(s) con error de sintaxis${NC}"
    fi
  fi

  # Count total rule IDs loaded
  local rule_ids=0
  if [ "$RULES_DOWNLOADED" -gt 0 ]; then
    rule_ids=$(grep -r "^  - id:" "$RULES_DIR" 2>/dev/null | wc -l | tr -d ' ')
    rule_ids=$((rule_ids + 0))
  fi

  echo ""
  echo -e "  ${DIM}Custom: ${RULES_DOWNLOADED}/${total} archivos | ${rule_ids} reglas cargadas${NC}"
  echo -e "  ${DIM}Community: semgrep registry (auto-update, ~3000+ reglas)${NC}"
  echo ""
}

# ─── Gitleaks ─────────────────────────────────────────────────

run_gitleaks() {
  echo -e "${BOLD}═══ Secretos (Gitleaks) ═══${NC}"
  echo ""

  local gl_report
  gl_report=$(mktemp)

  gitleaks detect --source="$TARGET" --report-format json --report-path "$gl_report" 2>/dev/null || true

  SECRETS_COUNT=$(python3 -c "
import sys, json
try:
    data = json.load(open('$gl_report'))
    print(len(data) if isinstance(data, list) else 0)
except:
    print(0)
" 2>/dev/null || echo 0)
  SECRETS_COUNT=$((SECRETS_COUNT + 0))

  if [ "$SECRETS_COUNT" -gt 0 ]; then
    echo -e "  ${RED}⚠ ${SECRETS_COUNT} secreto(s) detectado(s):${NC}"
    echo ""
    python3 -c "
import json
data = json.load(open('$gl_report'))
for finding in data:
    rule = finding.get('RuleID', '?')
    file = finding.get('File', '?')
    line = finding.get('StartLine', '?')
    print(f'    RuleID: {rule}')
    print(f'    File:   {file}:{line}')
    print()
" 2>/dev/null || true
  else
    echo -e "  ${GREEN}✓ Sin secretos detectados${NC}"
  fi

  rm -f "$gl_report"
  echo ""
}

# ─── OSV-Scanner (dependencias) ───────────────────────────────

run_osv_scanner() {
  if ! command -v osv-scanner &>/dev/null; then
    return 0
  fi

  echo -e "${BOLD}═══ Dependencias (OSV-Scanner) ═══${NC}"
  echo ""

  local osv_report
  osv_report=$(mktemp)

  osv-scanner scan -r "$TARGET" --format json > "$osv_report" 2>/dev/null
  local exit_code=$?

  case $exit_code in
    0)
      echo -e "  ${GREEN}✓ Sin vulnerabilidades conocidas en dependencias${NC}"
      ;;
    1)
      OSV_COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('$osv_report'))
    groups = set()
    for result in data.get('results', []):
        for pkg in result.get('packages', []):
            for group in pkg.get('groups', []):
                for gid in group.get('ids', []):
                    groups.add(gid)
    print(len(groups))
except:
    print(0)
" 2>/dev/null || echo 0)
      OSV_COUNT=$((OSV_COUNT + 0))

      echo -e "  ${RED}⚠ ${OSV_COUNT} vulnerabilidad(es) en dependencias:${NC}"
      echo ""
      python3 -c "
import json
data = json.load(open('$osv_report'))
for result in data.get('results', []):
    source = result.get('source', {}).get('path', '?')
    for pkg in result.get('packages', []):
        name = pkg.get('package', {}).get('name', '?')
        version = pkg.get('package', {}).get('version', '?')
        ecosystem = pkg.get('package', {}).get('ecosystem', '?')
        vulns = pkg.get('vulnerabilities', [])
        ids = [v.get('id', '?') for v in vulns[:3]]
        ids_str = ', '.join(ids)
        if len(vulns) > 3:
            ids_str += f' (+{len(vulns)-3} más)'
        print(f'    {name}@{version} ({ecosystem})')
        print(f'      {ids_str}')
        print()
" 2>/dev/null || true
      ;;
    128)
      echo -e "  ${DIM}○ No se encontraron lockfiles en el proyecto (saltando)${NC}"
      ;;
    *)
      echo -e "  ${YELLOW}○ Error ejecutando osv-scanner (código: ${exit_code})${NC}"
      ;;
  esac

  rm -f "$osv_report"
  echo ""
}

# ─── Semgrep ──────────────────────────────────────────────────

run_semgrep() {
  echo -e "${BOLD}═══ Código (Semgrep SAST) ═══${NC}"
  echo ""

  # Custom rules
  if [ "$RULES_DOWNLOADED" -gt 0 ]; then
    echo -e "  ${CYAN}── Reglas custom (myshoptree) ──${NC}"
    echo ""
    local custom_output
    custom_output=$(semgrep scan --config="$RULES_DIR" --json --quiet "$TARGET" 2>/dev/null) || true

    local count
    count=$(echo "$custom_output" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo 0)
    SEMGREP_CUSTOM_COUNT=$((count + 0))

    if [ "$SEMGREP_CUSTOM_COUNT" -gt 0 ]; then
      echo -e "  ${RED}⚠ ${SEMGREP_CUSTOM_COUNT} hallazgo(s)${NC}"
      echo ""
      echo "$custom_output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('results', []):
    path = r.get('path','?')
    line = r.get('start',{}).get('line','?')
    rule = r.get('check_id','?').split('.')[-1]
    severity = r.get('extra',{}).get('severity','?')
    print(f'    {severity:<8} {rule}')
    print(f'             {path}:{line}')
    print()
" 2>/dev/null || true
    else
      echo -e "  ${GREEN}✓ Sin hallazgos${NC}"
      echo ""
    fi
  fi

  # Community rules
  echo -e "  ${CYAN}── Reglas community (semgrep registry) ──${NC}"
  echo ""
  local community_output
  community_output=$(semgrep scan --config=auto --json --quiet "$TARGET" 2>/dev/null) || true

  local count
  count=$(echo "$community_output" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo 0)
  SEMGREP_COMMUNITY_COUNT=$((count + 0))

  if [ "$SEMGREP_COMMUNITY_COUNT" -gt 0 ]; then
    echo -e "  ${RED}⚠ ${SEMGREP_COMMUNITY_COUNT} hallazgo(s)${NC}"
    echo ""
    echo "$community_output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
seen = set()
for r in data.get('results', []):
    path = r.get('path','?')
    line = r.get('start',{}).get('line','?')
    rule = r.get('check_id','?').split('.')[-1]
    severity = r.get('extra',{}).get('severity','?')
    msg = r.get('extra',{}).get('message','').split('.')[0]
    key = f'{rule}:{path}:{line}'
    if key not in seen:
        seen.add(key)
        print(f'    {severity:<8} {rule}')
        print(f'             {path}:{line}')
        if msg:
            print(f'             {msg[:80]}')
        print()
" 2>/dev/null || true
  else
    echo -e "  ${GREEN}✓ Sin hallazgos${NC}"
    echo ""
  fi

}

# ─── Summary ─────────────────────────────────────────────────

summary() {
  local total=$((SECRETS_COUNT + SEMGREP_CUSTOM_COUNT + SEMGREP_COMMUNITY_COUNT + OSV_COUNT))

  echo -e "${CYAN}┌──────────────────────────────────────────────┐${NC}"
  echo -e "${CYAN}│           ${BOLD}RESUMEN DE SEGURIDAD${NC}${CYAN}               │${NC}"
  echo -e "${CYAN}├──────────────────────────────────────────────┤${NC}"

  if [ "$SECRETS_COUNT" -gt 0 ]; then
    printf "${CYAN}│${NC}  ${RED}⚠${NC}  Secretos expuestos:    ${BOLD}%-5s${NC}${CYAN}│${NC}\n" "$SECRETS_COUNT"
  else
    printf "${CYAN}│${NC}  ${GREEN}✓${NC}  Secretos expuestos:    %-5s${CYAN}│${NC}\n" "0"
  fi

  if [ "$OSV_COUNT" -gt 0 ]; then
    printf "${CYAN}│${NC}  ${RED}⚠${NC}  Dependencias (OSV):    ${BOLD}%-5s${NC}${CYAN}│${NC}\n" "$OSV_COUNT"
  else
    printf "${CYAN}│${NC}  ${GREEN}✓${NC}  Dependencias (OSV):    %-5s${CYAN}│${NC}\n" "0"
  fi

  if [ "$SEMGREP_CUSTOM_COUNT" -gt 0 ]; then
    printf "${CYAN}│${NC}  ${RED}⚠${NC}  SAST custom rules:     ${BOLD}%-5s${NC}${CYAN}│${NC}\n" "$SEMGREP_CUSTOM_COUNT"
  else
    printf "${CYAN}│${NC}  ${GREEN}✓${NC}  SAST custom rules:     %-5s${CYAN}│${NC}\n" "0"
  fi

  if [ "$SEMGREP_COMMUNITY_COUNT" -gt 0 ]; then
    printf "${CYAN}│${NC}  ${RED}⚠${NC}  SAST community rules:  ${BOLD}%-5s${NC}${CYAN}│${NC}\n" "$SEMGREP_COMMUNITY_COUNT"
  else
    printf "${CYAN}│${NC}  ${GREEN}✓${NC}  SAST community rules:  %-5s${CYAN}│${NC}\n" "0"
  fi

  echo -e "${CYAN}├──────────────────────────────────────────────┤${NC}"
  printf "${CYAN}│${NC}     Total hallazgos:      ${BOLD}%-5s${NC}             ${CYAN}│${NC}\n" "$total"
  echo -e "${CYAN}└──────────────────────────────────────────────┘${NC}"
  echo ""

  if [ "$total" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠ Revisar hallazgos antes de desplegar a producción.${NC}"
  else
    echo -e "  ${GREEN}✓ El proyecto no presenta vulnerabilidades conocidas.${NC}"
  fi
  echo ""

  return "$total"
}

# ─── Main ─────────────────────────────────────────────────────

banner
check_deps
check_rules
run_gitleaks
run_osv_scanner
run_semgrep
summary || exit 1
