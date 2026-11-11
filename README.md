# HeaderShield

> Audita cabeceras HTTP de seguridad y genera un informe local y accionable.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Español

**HeaderShield** es un CLI sin dependencias para una primera revisión defensiva de la postura de cabeceras HTTP de cualquier URL pública. Analiza las cabeceras de respuesta, muestra qué controles faltan y propone mejoras prácticas. No realiza explotación, escaneo de puertos ni cambios sobre el objetivo.

### Qué revisa

- **HTTPS y redirecciones**: detecta si la URL final usa HTTPS.
- **HSTS**: comprueba `Strict-Transport-Security`.
- **Antiinyección de contenido**: `Content-Security-Policy` y `X-Content-Type-Options`.
- **Protección de framing**: `X-Frame-Options` o `frame-ancestors` en CSP.
- **Privacidad**: `Referrer-Policy` y `Permissions-Policy`.
- Puntuación explicable sobre 100 con hallazgos priorizados.

### Uso rápido

```bash
git clone https://github.com/alvaroalcalaa/headershield.git
cd headershield
python headershield.py https://example.com
```

Guardar el informe en Markdown:

```bash
python headershield.py https://example.com --format markdown --output report.md
```

Ejecutar la demo sin conexión:

```bash
python headershield.py --headers-file examples/weak_headers.json
```

### Ejemplo de salida

```text
HeaderShield · https://demo.local
Score: 42/100 · Needs attention

[HIGH] Content-Security-Policy is missing
       Add a restrictive CSP and tune it with report-only mode first.
[PASS] X-Content-Type-Options: nosniff
[MEDIUM] Referrer-Policy is missing
       Prefer strict-origin-when-cross-origin or stricter.
```

### Estructura

```text
headershield/
├── headershield.py       # CLI y motor de evaluación
├── examples/
│   └── weak_headers.json # Demo reproducible sin red
├── tests.py              # Casos de evaluación
├── README.md
└── LICENSE
```

### Nota de uso responsable

Úsalo únicamente sobre servicios propios o con autorización. La utilidad está pensada para visibilidad defensiva; una buena puntuación no sustituye una revisión de seguridad profesional.

## English

**HeaderShield** is a dependency-free CLI for an initial, defensive review of an HTTP security-header posture for a public URL. It evaluates response headers, highlights missing controls, and suggests practical improvements. It does not exploit targets, scan ports, or modify systems.

### What it checks

- **HTTPS and redirects** on the final URL.
- **HSTS** via `Strict-Transport-Security`.
- **Content-injection defenses**: `Content-Security-Policy` and `X-Content-Type-Options`.
- **Frame protection**: `X-Frame-Options` or CSP `frame-ancestors`.
- **Privacy controls**: `Referrer-Policy` and `Permissions-Policy`.
- An explainable 0–100 score with prioritized findings.

### Quick start

```bash
python headershield.py https://example.com --format markdown
python -m unittest tests.py
```

## License

MIT — see [LICENSE](LICENSE).
