# sec-shield-semgrep

Security scanner para proyectos myshoptree. Ejecuta Gitleaks (secretos) + Semgrep (SAST) con reglas custom para el stack NestJS/TypeScript/Mongoose.

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

## Reglas custom incluidas

| Regla | Detecta |
|-------|---------|
| `mongoose-nosql-injection` | NoSQL injection via operadores Mongoose ($where, $regex, etc.) |
| `js-sqli` | SQL injection por concatenación de strings |
| `axios-resource-injection` | SSRF/resource injection en llamadas HTTP |
| `exec-injection` | Command injection via exec() |
| `jwt-misconfig` | JWT sin algoritmo explícito o con 'none' |
| `insecure-cookie` | Cookies sin secure/httpOnly |

## Requisitos

- `semgrep` (se auto-instala via pip3 o brew)
- `gitleaks` (se auto-instala via brew o binary)

## Estructura

```
sec-shield-semgrep/
├── sec-shield.sh              # Script principal (entry point)
├── install-hook.sh      # Instalador de pre-push hook
├── rules/               # Reglas Semgrep custom
│   ├── mongoose-nosql-injection.yml
│   ├── js-sqli.yml
│   ├── axios-resource-injection.yml
│   ├── exec-injection.yml
│   ├── jwt-misconfig.yml
│   └── insecure-cookie.yml
└── test_samples/        # Muestras para validar reglas
```
