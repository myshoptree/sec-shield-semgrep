# sec-shield-semgrep

Security scanner CLI para proyectos myshoptree. Ejecuta múltiples herramientas de seguridad con reglas custom para el stack NestJS/TypeScript/Mongoose.

## Qué escanea

| Motor | Categoría | Descripción |
|-------|-----------|-------------|
| **Gitleaks** | Secretos | API keys, tokens, passwords expuestos en el código |
| **OSV-Scanner** | Dependencias | Vulnerabilidades conocidas en paquetes (npm, pip, go, etc.) |
| **Semgrep (custom)** | SAST | Reglas propias para el stack myshoptree |
| **Semgrep (community)** | SAST | +3000 reglas de la comunidad Semgrep |

## Uso rápido

Escanear el directorio actual:

```bash
curl -fsSL https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/sec-shield.sh | bash -s .
```

Escanear un directorio específico:

```bash
curl -fsSL https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/sec-shield.sh | bash -s /path/to/repo
```

## Instalar como pre-push hook

```bash
cd tu-repo
curl -fsSL https://raw.githubusercontent.com/myshoptree/sec-shield-semgrep/main/install-hook.sh | bash
```

## Requisitos

**Obligatorios:**

- `python3`
- `semgrep` — SAST multi-lenguaje
- `gitleaks` — detección de secretos

**Opcional:**

- `osv-scanner` — escaneo de dependencias vulnerables (si no está instalado, se salta)

### Instalación (macOS)

```bash
brew install semgrep gitleaks osv-scanner
```

### Variables de entorno

| Variable | Uso |
|----------|-----|
| `GITHUB_TOKEN` | Opcional. Evita rate-limits en chequeos de versión contra GitHub API |

## Reglas custom incluidas

| Regla | Detecta |
|-------|---------|
| `mongoose-nosql-injection` | NoSQL injection via operadores Mongoose ($where, $regex, etc.) |
| `js-sqli` | SQL injection por concatenación de strings |
| `axios-resource-injection` | SSRF/resource injection en llamadas HTTP |
| `exec-injection` | Command injection via exec() |
| `jwt-misconfig` | JWT sin algoritmo explícito o con 'none' |
| `insecure-cookie` | Cookies sin secure/httpOnly |
| `ai-agent-hook-injection` | Inyección de prompts en agentes AI |
| `supply-chain-payload` | Payloads maliciosos en dependencias |
| `malicious-instructions` | Instrucciones ocultas en paquetes |

Las reglas se cargan dinámicamente desde `rules/manifest.txt`. Para agregar una regla nueva, solo añadí su nombre al manifest y el archivo `.yml` correspondiente.

## Exit codes

| Código | Significado |
|--------|-------------|
| `0` | Sin hallazgos |
| `1` | Hallazgos detectados (útil para CI/CD) |

## Estructura

```
sec-shield-semgrep/
├── sec-shield.sh          # Script principal (entry point)
├── install-hook.sh        # Instalador de pre-push hook
├── rules/                 # Reglas Semgrep custom
│   ├── manifest.txt       # Lista dinámica de reglas
│   ├── mongoose-nosql-injection.yml
│   ├── js-sqli.yml
│   ├── axios-resource-injection.yml
│   ├── exec-injection.yml
│   ├── jwt-misconfig.yml
│   ├── insecure-cookie.yml
│   ├── ai-agent-hook-injection.yml
│   ├── supply-chain-payload.yml
│   └── malicious-instructions.yml
└── test_samples/          # Muestras para validar reglas
```

## Características

- Chequeo automático de versiones (semgrep, gitleaks, osv-scanner)
- Soporte para `GITHUB_TOKEN` (evita rate-limits en CI)
- Limpieza automática de archivos temporales (trap en EXIT/INT/TERM)
- Deduplicación de hallazgos
- Manifest dinámico de reglas (no requiere actualizar el script para agregar reglas)
- Exit code semántico para integración con CI/CD
