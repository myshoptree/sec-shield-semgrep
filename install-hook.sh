#!/usr/bin/env bash
set -euo pipefail

# Instala el pre-push hook en el repo actual
# Usage: curl -fsSL https://raw.githubusercontent.com/<org>/sec-shield-semgrep/main/install-hook.sh | bash

SCAN_URL="https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/sec-shield.sh"
HOOK_PATH=".git/hooks/pre-push"

if [ ! -d ".git" ]; then
  echo "Error: no estás en la raíz de un repositorio git"
  exit 1
fi

mkdir -p .git/hooks

cat > "$HOOK_PATH" << 'EOF'
#!/usr/bin/env bash
echo "Running sec-shield-semgrep pre-push scan..."
curl -fsSL "https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/sec-shield.sh" | bash -s .
EOF

chmod +x "$HOOK_PATH"
echo "✔ Pre-push hook instalado en ${HOOK_PATH}"
