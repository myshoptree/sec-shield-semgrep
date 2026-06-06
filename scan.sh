#!/usr/bin/env bash
set -euo pipefail

# sec-shield-semgrep scanner
# Usage: curl -fsSL https://raw.githubusercontent.com/<org>/sec-shield-semgrep/main/scan.sh | bash -s .

RULES_REPO="https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/rules"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BLOCKED=false

TARGET="${1:-.}"

banner() {
  echo ""
  echo -e "${YELLOW}╔══════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║     sec-shield-semgrep scanner       ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════╝${NC}"
  echo ""
}

check_deps() {
  local missing=()

  if ! command -v semgrep &>/dev/null; then
    missing+=("semgrep")
  fi

  if ! command -v gitleaks &>/dev/null; then
    missing+=("gitleaks")
  fi

  if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${YELLOW}[!] Dependencias faltantes: ${missing[*]}${NC}"
    echo ""
    install_deps "${missing[@]}"
  fi
}

install_deps() {
  local deps=("$@")

  for dep in "${deps[@]}"; do
    case "$dep" in
      semgrep)
        echo -e "${YELLOW}[*] Instalando semgrep...${NC}"
        if command -v pip3 &>/dev/null; then
          pip3 install semgrep --quiet
        elif command -v brew &>/dev/null; then
          brew install semgrep
        else
          echo -e "${RED}[✗] No se pudo instalar semgrep. Instala pip3 o brew.${NC}"
          exit 1
        fi
        ;;
      gitleaks)
        echo -e "${YELLOW}[*] Instalando gitleaks...${NC}"
        if command -v brew &>/dev/null; then
          brew install gitleaks
        else
          local GL_VERSION="8.21.2"
          local OS=$(uname -s | tr '[:upper:]' '[:lower:]')
          local ARCH=$(uname -m)
          [ "$ARCH" = "x86_64" ] && ARCH="x64"
          [ "$ARCH" = "aarch64" ] && ARCH="arm64"
          curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VERSION}/gitleaks_${GL_VERSION}_${OS}_${ARCH}.tar.gz" | tar -xz -C /tmp
          sudo mv /tmp/gitleaks /usr/local/bin/
        fi
        ;;
    esac
  done
  echo ""
}

run_gitleaks() {
  echo -e "${YELLOW}[1/2] Gitleaks — escaneando secretos...${NC}"

  if gitleaks detect --source="$TARGET" --no-banner --exit-code 0 -v 2>/dev/null | grep -q "Finding:"; then
    echo -e "${RED}[✗] Secretos detectados:${NC}"
    gitleaks detect --source="$TARGET" --no-banner 2>/dev/null || true
    BLOCKED=true
  else
    if gitleaks detect --source="$TARGET" --no-banner 2>/dev/null; then
      echo -e "${GREEN}[✓] Sin secretos detectados${NC}"
    else
      echo -e "${RED}[✗] Secretos detectados${NC}"
      gitleaks detect --source="$TARGET" --no-banner -v 2>/dev/null || true
      BLOCKED=true
    fi
  fi
  echo ""
}

run_semgrep() {
  echo -e "${YELLOW}[2/2] Semgrep — análisis estático de seguridad...${NC}"

  local rules_dir=$(mktemp -d)
  local rule_files=("mongoose-nosql-injection" "js-sqli" "axios-resource-injection" "exec-injection" "jwt-misconfig" "insecure-cookie")

  for rule in "${rule_files[@]}"; do
    curl -sSfL "${RULES_REPO}/${rule}.yml" -o "${rules_dir}/${rule}.yml" 2>/dev/null || true
  done

  local downloaded=$(find "$rules_dir" -name "*.yml" | wc -l | tr -d ' ')

  if [ "$downloaded" -eq 0 ]; then
    echo -e "${YELLOW}[!] No se pudieron descargar reglas custom, usando solo community rules${NC}"
    if semgrep scan --config=auto --severity=ERROR --quiet "$TARGET" 2>/dev/null; then
      echo -e "${GREEN}[✓] Sin hallazgos críticos${NC}"
    else
      echo -e "${RED}[✗] Hallazgos críticos encontrados${NC}"
      BLOCKED=true
    fi
  else
    echo "    Reglas custom cargadas: ${downloaded}"
    local findings=0

    # Custom rules
    if ! semgrep scan --config="$rules_dir" --severity=ERROR --quiet "$TARGET" 2>/dev/null; then
      echo -e "${RED}[✗] Hallazgos en reglas custom:${NC}"
      semgrep scan --config="$rules_dir" --severity=ERROR "$TARGET" 2>/dev/null || true
      findings=1
    fi

    # Community rules
    if ! semgrep scan --config=auto --severity=ERROR --quiet "$TARGET" 2>/dev/null; then
      echo -e "${RED}[✗] Hallazgos en reglas community:${NC}"
      semgrep scan --config=auto --severity=ERROR "$TARGET" 2>/dev/null || true
      findings=1
    fi

    if [ "$findings" -eq 0 ]; then
      echo -e "${GREEN}[✓] Sin hallazgos críticos${NC}"
    else
      BLOCKED=true
    fi
  fi

  rm -rf "$rules_dir"
  echo ""
}

summary() {
  echo -e "${YELLOW}══════════════════════════════════════${NC}"
  if [ "$BLOCKED" = true ]; then
    echo -e "${RED}  RESULTADO: BLOQUEADO${NC}"
    echo -e "${RED}  Se encontraron problemas de seguridad.${NC}"
    echo -e "${YELLOW}══════════════════════════════════════${NC}"
    exit 1
  else
    echo -e "${GREEN}  RESULTADO: APROBADO${NC}"
    echo -e "${GREEN}  No se encontraron problemas críticos.${NC}"
    echo -e "${YELLOW}══════════════════════════════════════${NC}"
    exit 0
  fi
}

banner
check_deps
run_gitleaks
run_semgrep
summary
