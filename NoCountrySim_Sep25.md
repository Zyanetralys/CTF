# Simulación Laboral Septiembre 2025 - No Country

## Información
**Programa:** Simulación Laboral No Country  
**Período:** 29 septiembre - 3 noviembre 2025  
**Rol:** Ethical Hacker  

## Programa
Simulación laboral intensiva de 5 semanas diseñada para replicar entornos de trabajo reales en equipos multidisciplinarios. El programa abarca múltiples especialidades tecnológicas incluyendo desarrollo web, mobile, ciberseguridad, AI, UX/UI design, data science y marketing digital.

## Metodología
- **Metodología:** Framework Agile/Scrum con sprints semanales
- **Formato:** Trabajo colaborativo en equipos balanceados
- **Modalidad:** 100% remoto con reuniones obligatorias
- **Duración:** 5 semanas (Semana 0 + 4 semanas de desarrollo)

## Cronograma de Actividades

### Semana 0 - Planificación
- Formación de equipos mediante análisis de perfiles y matching por roles
- Sprint Planning obligatorio
- Presentación de integrantes y definición de roles
- Sprint Demo y feedback inicial

### Semanas 1-3 - Ejecución
- Sprint Planning semanal (reuniones obligatorias)
- Daily meetings para coordinación de actividades
- Desarrollo incremental del proyecto
- Sprint Demos semanales
- Gestión de recursos y entregables

### Semana 4 - Presentación
- Finalización de desarrollos
- Preparación de entregables finales
- Creación de video demo del proyecto
- Demo Day comunitario
- Evaluación y feedback entre compañeros

## Competencias
- **Trabajo en equipo multidisciplinario:** Colaboración efectiva con profesionales de diferentes especialidades
- **Metodologías ágiles:** Implementación práctica de Scrum en proyectos reales
- **Gestión de proyectos:** Planificación, ejecución y seguimiento de sprints
- **Comunicación técnica:** Presentaciones de avances y demos técnicas
- **Ciberseguridad aplicada:** Desarrollo de soluciones desde perspectiva de ethical hacking

## Herramientas
- Plataforma No Country para gestión de proyectos
- Discord para comunicación y coordinación de equipo
- ChatGPT para asistencia en desarrollo
- Herramientas de desarrollo específicas según proyecto asignado

## Objetivos
- Experiencia práctica en entornos de trabajo remoto
- Desarrollo de habilidades de colaboración interprofesional
- Implementación de buenas prácticas en ciberseguridad
- Creación de portfolio con proyecto real
- Networking con profesionales de la industria tech

## Resultados
- Proyecto completamente funcional desarrollado en equipo
- Video demostración técnica del producto
- Certificación de participación en simulación laboral
- Feedback profesional de pares y mentores
- Ampliación de red de contactos profesionales

---


🔐 Autenticación & Autorización
Recomendaciones clave

MFA obligatorio → Admins, accesos a producción, operaciones sensibles.

Opciones: TOTP (Google Authenticator), Okta (IdP empresarial), YubiKey para admins.

OAuth2 / OIDC → Scopes mínimos: openid profile email read:transactions write:transactions.

JWT → access_token 15m, refresh_token 7d, rotación y revocación.

Reautenticación → operaciones > €1,000 o cambios de KYC.

Ejemplo: integración básica Okta (Node.js)
// okta client
const okta = require('@okta/okta-sdk-nodejs');
const client = new okta.Client({
  orgUrl: process.env.OKTA_ORG_URL,
  token: process.env.OKTA_API_TOKEN
});

// verify MFA (ejemplo conceptual)
async function verifyMFA(userId, factorId, passCode) {
  const user = await client.getUser(userId);
  const factor = await user.getFactor(factorId);
  const verification = await factor.verify({ passCode });
  return verification.status === 'SUCCESS';
}

YubiKey (Linux PAM)
sudo apt install -y libpam-yubico
# Añadir al /etc/pam.d/common-auth
# auth required pam_yubico.so id=YOUR_CLIENT_ID key=YOUR_SECRET_KEY

🔑 Gestión de Credenciales & Secrets
Principios

Principio de menor privilegio.

No hardcodear secrets.

Gestor de secrets obligatorio: HashiCorp Vault / GCP Secret Manager / AWS Secrets Manager.

Rotación automática: claves rotadas cada 90 días.

Alerta y revocación inmediata ante compromiso.

Ejemplo: Vault — política mínima (HCL)
path "secret/data/fintech/*" {
  capabilities = ["read", "list"]
}
path "secret/data/prod/*" {
  capabilities = ["read"]
  allowed_parameters = {}
}

👥 Control de Accesos — RBAC (matriz rápida)
Rol	Permisos principales	MFA	Despliegue Prod
Admin	CRUD infraestructura, IAM, pagos	Sí	Manual/2 personas
DevOps	Deploy, infra, logs	Sí	Sí (CI gated)
Developer	Código, staging	No	No
Support	Logs anonimizados, solo lectura	No	No
Auditor	Read-only logs/config	Sí	No

Revisar permisos: cada 3 meses.

Segregación de funciones: dev ≠ deploy.

📊 Retención de Datos & Compliance

PII: retención mínima necesaria por ley; anonimizar cuando sea posible.

Datos de tarjeta: nunca almacenar CVV; usar tokenización (Stripe/PCI provider).

Logs de seguridad: conservar ≥ 1 año.

Logs de transacciones: según normativa financiera (ej. 5-7 años).

Backups: cifrados, retención 30 días (ej. GCS/AWS S3 con SSE + KMS).

Eliminación: borrado con registro de auditoría + destrucción criptográfica.

🖥️ Hardening & Infraestructura
Linux (CIS / comandos)
sudo apt update && sudo apt upgrade -y
# UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443/tcp
sudo ufw enable
# SSH
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
# Fail2Ban
sudo apt install -y fail2ban

Docker

No ejecutar contenedores como root → USER 1001 en Dockerfile.

Escanear imágenes: Trivy / Clair.

daemon.json ejemplo:

{
  "live-restore": true,
  "userland-proxy": false,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}

Red / Cloud

VPC segmentada: public LB, private API, data subnet sin acceso público.

IAM: roles por servicio, no users. Revisión trimestral.

🔒 Cifrado & Protección de Datos
En tránsito

TLS 1.2/1.3, HSTS, CSP, security headers en Nginx.

Ejemplo Nginx (extracto):

ssl_protocols TLSv1.2 TLSv1.3;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'" always;

En reposo

PostgreSQL: pgcrypto / TDE (cloud KMS).

Cloud KMS sample (gcloud):

gcloud kms keyrings create fintech-keyring --location=europe-west1
gcloud kms keys create data-encryption-key --location=europe-west1 --keyring=fintech-keyring --purpose=encryption

Tokenización pagos (Stripe)

Token en frontend (Stripe.js), backend procesa token y guarda solo last4 + brand.

🛡️ SDLC Seguro — Herramientas & Pipelines
SAST (Semgrep)

Config: p/owasp-top-ten, reglas custom hardcoded-secret, sql-injection.

Comando: semgrep --config=auto src/

DAST

OWASP ZAP baseline en staging, Burp para revisión manual.

ZAP Docker baseline:

docker run -u zap -p 8080:8080 \
  -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable \
  zap-baseline.py -t https://staging.example.com -r zap-report.html

SCA

npm audit, snyk test, Dependabot weekly.

Integrar en CI (GitHub Actions/GitLab CI).

Pipelines (snippet security job)
# .github/workflows/security.yml - excerpt
jobs:
  secret-scanning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2

🔎 Secret Scanning & Repo Hygiene

Tools: Gitleaks, TruffleHog, git-secrets (pre-commit hooks).

CI: bloquear PRs con secrets detectados.

.gitleaks.toml reglas: AWS, Stripe, jwt secret patterns.

🧰 Pentesting / Ethical Hacker — Checklist por sprint
Sprint 0 (Planificación)

Definir scopes, assets, reglas de engagement.

Entregables: scope.txt, rules_of_engagement.md.

Semana 1

Recon pasivo (OSINT, subdomains, cert transparency).

Crear lista targets y honeytokens.

Semana 2

Scanning (nuclei, trivy, semgrep).

DAST básico (ZAP baseline).

Semana 3

Explotación controlada en staging.

Privilege escalation checks, IAM policies review.

Semana 4 (final)

Reporte: executive summary + technical annex.

Remediation plan + retest checklist.

🐝 Honeytokens & Detectores (prácticos)

Credenciales falsas en repos, DB seeding (fake_user_zz), monitor alert on use.

Files: secrets-not-for-production.txt (URL unico, webhook).

Honeytoken delivery: alert Slack + create ticket automáticamente.

🚨 Monitoreo & Alertas — Umbrales sugeridos
ELK + Filebeat

Alerts: failed login rate rate(failed_login_attempts_total[5m]) > 10 → warn.

SQL injection detected → critical immediate.

Prometheus Alerts (ejemplo resumido)
- alert: HighFailedLoginRate
  expr: rate(failed_login_attempts_total[5m]) > 10
  for: 2m
  labels: { severity: warning }


DDoS early: rate(http_requests_total[5m]) > 1000 → investigate.

⚠️ Threat Model (STRIDE) — Mitigaciones directas

Spoofing → MFA + cert pinning en mobile.

Tampering → TLS mutual en segmentos interns, signatures.

Repudiation → audit logs WORM, centralizado.

Information Disclosure → no PII en logs, data redaction.

DoS → rate limits, autoscaling + WAF.

Elevation → IAM least privilege, periodic IAM review.

🧾 Incident Response — Playbook (resumen)

Detección → alert SRE/SEC + ticket automatic.

Triage → clasificar (confidencialidad/integridad/disponibilidad).

Containment → rotar claves, bloquear IPs, aislar pods.

Eradication → eliminar backdoor/honeytoken, parche.

Recovery → restore from backup cifrado, validación integridad.

Post-mortem → informe, lessons learned, aplicar mitigations.

📁 Entregables para Demo Day (qué llevar)

Executive summary (1 página).

Matriz de controles (Control | Herramienta | Estado).

Listado de vulnerabilidades críticas + PRs creados.

Video demo: despliegue seguro + prueba de exploit mitigada.

Checklist de despliegue seguro para producción.

✅ Lista rápida (Checklist ejecutable)

 MFA en cuentas admin (Okta/TOTP/YubiKey)

 Secrets en Vault / no hardcoded

 SAST + DAST + SCA integrados en CI

 WAF + Rate limiting + CDN rules

 Backups cifrados + KMS

 Logs → ELK + alertas configuradas

 RBAC revisado (últimos 3 meses)

 Playbook IR validado y comunicado

 ---






# Kit de Seguridad para Super App Financiera

## Inventario de Activos y Arquitectura

### Componentes Críticos
- **Frontend**: Aplicación web (React/Angular) y móvil (iOS/Android)
- **Backend API**: Servicios REST/GraphQL para transacciones, autenticación, pagos
- **Base de datos**: PostgreSQL con datos PII y transacciones financieras
- **Servicios externos**: Pasarelas de pago, KYC/AML providers, servicios de notificación
- **Infraestructura**: Contenedores Docker en cloud (GCP/AWS), balanceadores, CDN

### Clasificación de Datos
- **Críticos**: Datos de tarjetas, contraseñas, tokens de sesión, claves API
- **Sensibles**: PII (nombres, DNI, dirección), historial de transacciones
- **Internos**: Logs, métricas, configuraciones
- **Públicos**: Documentación, términos de servicio

### Diagrama de Flujo
Usuario → CDN → Load Balancer → API Gateway → Microservicios
↓
Base de Datos (cifrada)
↓
Proveedores externos (TLS)

### Threat Model (STRIDE)
- **Spoofing**: Suplantación de identidad sin MFA
- **Tampering**: Modificación de transacciones en tránsito sin TLS
- **Repudiation**: Falta de logs de auditoría
- **Information Disclosure**: Exposición de tokens o datos en logs
- **Denial of Service**: Falta de rate limiting en APIs
- **Elevation of Privilege**: Permisos excesivos en roles IAM

---

## Políticas de Seguridad

### Política de Contraseñas

**Requisitos mínimos**:
- Longitud mínima: 12 caracteres (recomendado 16+)
- Uso de passphrases en lugar de combinaciones complejas arbitrarias
- No forzar rotación periódica sin causa justificada
- Validar contra listas de contraseñas comprometidas (Have I Been Pwned API)
- Prohibir contraseñas comunes (password123, qwerty, etc.)

**Almacenamiento**:
- NUNCA almacenar en texto plano
- Usar bcrypt, Argon2 o PBKDF2 con salt único
- Aplicar hashing en backend antes de almacenar

**MFA obligatorio para**:
- Cuentas administrativas
- Acceso a producción
- Transacciones superiores a umbral definido

### Política de Gestión de Credenciales

**Principios**:
- Principio de menor privilegio
- Rotación automática de claves cada 90 días
- Prohibido hardcodear secrets en código fuente
- Uso obligatorio de gestores de secrets (GCP Secret Manager, HashiCorp Vault)

**Gestión de API Keys**:
- Generar keys con scope limitado
- Revocar inmediatamente si hay compromiso
- Monitorear uso anormal de APIs

**Acceso a producción**:
- Requiere MFA + VPN
- Logs de todas las sesiones
- Revisión trimestral de permisos

### Política de Control de Acceso

**Roles definidos**:
- **Admin**: acceso total (solo 2-3 personas)
- **DevOps**: deploy, infraestructura, logs
- **Developer**: desarrollo, staging
- **Support**: solo lectura de logs y datos anonimizados
- **Auditor**: acceso read-only a logs y configuraciones

**Reglas**:
- Revisar permisos cada 3 meses
- Revocar accesos al cambiar de rol o salir de la empresa
- Segregación de funciones: quien desarrolla no despliega en prod

### Política de Retención de Datos

**Cumplimiento GDPR/PCI DSS**:
- Datos de tarjetas: no almacenar CVV nunca; tokenizar con proveedor PCI
- PII: retener solo mientras sea necesario, máximo según ley local
- Logs de seguridad: mínimo 1 año
- Logs de transacciones: según regulación financiera (5-7 años típicamente)
- Backups cifrados: retención 30 días

**Eliminación segura**:
- Borrado criptográfico (destruir claves de cifrado)
- Sobrescritura múltiple para soportes físicos
- Documentar todas las eliminaciones para auditoría

---

## Hardening de Infraestructura

### CIS Benchmarks - Linux

**Sistema operativo base**:

# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Deshabilitar servicios innecesarios
sudo systemctl disable cups bluetooth avahi-daemon

# Configurar firewall UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH (temporal, cambiar puerto)
sudo ufw allow 443/tcp # HTTPS
sudo ufw enable
sudo ufw logging on

# Configurar SSH seguro
sudo nano /etc/ssh/sshd_config
# Cambiar:
# Port 2222
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes
sudo systemctl restart sshd

# Instalar fail2ban
sudo apt install -y fail2ban
sudo systemctl enable fail2ban

## Auditd para monitoreo:
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd

# Configurar reglas básicas
sudo nano /etc/audit/rules.d/audit.rules
# Añadir:
# -w /etc/passwd -p wa -k identity
# -w /etc/shadow -p wa -k identity
# -w /var/log/auth.log -p wa -k auth

sudo systemctl restart auditd

CIS Benchmarks - Docker
Configuración segura de Docker:
# No ejecutar contenedores como root
docker run --user 1000:1000 myapp

# Limitar recursos
docker run --memory="512m" --cpus="1.0" myapp

# Usar imágenes oficiales y escanearlas
trivy image myapp:latest

# Configurar Docker daemon
sudo nano /etc/docker/daemon.json
{
  "live-restore": true,
  "userland-proxy": false,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}

sudo systemctl restart docker

Dockerfile seguro:
FROM node:18-alpine AS base

# Crear usuario no-root
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser

WORKDIR /app

# Copiar dependencias
COPY package*.json ./
RUN npm ci --only=production

# Copiar código
COPY --chown=appuser:appgroup . .

# Cambiar a usuario no-root
USER appuser

EXPOSE 3000
CMD ["node", "server.js"]

Segmentación de Red
Configurar VPC y subnets:

Subnet pública: Load balancer, bastion host
Subnet privada: APIs, microservicios
Subnet de datos: Bases de datos, sin acceso directo a internet

Reglas de firewall:
# Ejemplo GCP firewall rules
- name: allow-lb-to-backend
  source: load-balancer-subnet
  destination: backend-subnet
  ports: 8080

- name: allow-backend-to-db
  source: backend-subnet
  destination: database-subnet
  ports: 5432

- name: deny-all-default
  action: deny
  priority: 65534

  Autenticación y Autorización
Implementación de MFA
Opciones recomendadas:
TOTP (Time-based One-Time Password):

# Instalar Google Authenticator en servidor (PAM)
sudo apt install -y libpam-google-authenticator

# Configurar para usuario
google-authenticator
# Responder: yes, yes, yes, no, yes

# Editar PAM
sudo nano /etc/pam.d/sshd
# Añadir: auth required pam_google_authenticator.so

# Editar SSH
sudo nano /etc/ssh/sshd_config
# Cambiar: ChallengeResponseAuthentication yes
sudo systemctl restart sshd

Integración con Okta (ejemplo Node.js):
const okta = require('@okta/okta-sdk-nodejs');

const client = new okta.Client({
  orgUrl: 'https://dev-123456.okta.com',
  token: process.env.OKTA_API_TOKEN
});

// Verificar MFA
async function verifyMFA(userId, factorId, passCode) {
  const user = await client.getUser(userId);
  const factor = await user.getFactor(factorId);
  const verification = await factor.verify({ passCode });
  return verification.status === 'SUCCESS';
}

YubiKey para administradores:
# Instalar soporte YubiKey
sudo apt install -y libpam-yubico

# Configurar
sudo nano /etc/pam.d/common-auth
# Añadir: auth required pam_yubico.so id=YOUR_CLIENT_ID key=YOUR_SECRET_KEY

OAuth2 / OpenID Connect
Configuración de scopes:
// Ejemplo con Passport.js
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');

passport.use(new OAuth2Strategy({
    authorizationURL: 'https://auth.example.com/oauth/authorize',
    tokenURL: 'https://auth.example.com/oauth/token',
    clientID: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    callbackURL: 'https://app.example.com/callback',
    scope: ['read:profile', 'write:transactions']
  },
  function(accessToken, refreshToken, profile, cb) {
    // Validar y crear sesión
    return cb(null, profile);
  }
));

Gestión de Sesiones
Tokens JWT seguros:
const jwt = require('jsonwebtoken');

// Generar token
function generateToken(userId) {
  return jwt.sign(
    { userId, role: 'user' },
    process.env.JWT_SECRET,
    { 
      expiresIn: '15m',  // Token corto
      algorithm: 'HS256',
      issuer: 'myapp.com'
    }
  );
}

// Refresh token (almacenar en DB)
function generateRefreshToken(userId) {
  return jwt.sign(
    { userId, type: 'refresh' },
    process.env.REFRESH_SECRET,
    { expiresIn: '7d' }
  );
}

// Middleware de verificación
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

Configuración de sesiones:

Access token: 15 minutos
Refresh token: 7 días (revocar al logout)
Re-autenticación para operaciones sensibles (transferencias > $1000)
Invalidar todas las sesiones al cambiar contraseña


Protección de Datos
Cifrado en Tránsito (TLS)
Configurar certificados con Certbot:
# Instalar Certbot
sudo apt update
sudo apt install -y snapd
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Obtener certificado para Nginx
sudo certbot --nginx -d api.example.com -d www.example.com

# Verificar renovación automática
sudo certbot renew --dry-run

# Ver certificados instalados
sudo certbot certificates

Configuración Nginx con TLS robusto:
server {
    listen 443 ssl http2;
    server_name api.example.com;

    # Certificados
    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    # Protocolos y ciphers seguros
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location / {
        proxy_pass http://backend:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirigir HTTP a HTTPS
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}

Cifrado en Reposo
PostgreSQL con pgcrypto:
-- Activar extensión
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Crear tabla con columnas cifradas
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone_encrypted BYTEA,
    ssn_encrypted BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insertar datos cifrados (usar variable de entorno para key)
INSERT INTO users (email, phone_encrypted, ssn_encrypted) 
VALUES (
    'user@example.com',
    pgp_sym_encrypt('+34612345678', 'strong-encryption-key-here'),
    pgp_sym_encrypt('123-45-6789', 'strong-encryption-key-here')
);

-- Leer datos descifrados (solo en aplicación, no en logs)
SELECT 
    id,
    email,
    pgp_sym_decrypt(phone_encrypted, 'strong-encryption-key-here') AS phone,
    pgp_sym_decrypt(ssn_encrypted, 'strong-encryption-key-here') AS ssn
FROM users
WHERE email = 'user@example.com';

GCP Cloud KMS:
# Crear keyring
gcloud kms keyrings create fintech-keyring \
    --location=europe-west1

# Crear clave de cifrado
gcloud kms keys create data-encryption-key \
    --location=europe-west1 \
    --keyring=fintech-keyring \
    --purpose=encryption

# Cifrar archivo
gcloud kms encrypt \
    --location=europe-west1 \
    --keyring=fintech-keyring \
    --key=data-encryption-key \
    --plaintext-file=secrets.txt \
    --ciphertext-file=secrets.txt.enc

# Descifrar
gcloud kms decrypt \
    --location=europe-west1 \
    --keyring=fintech-keyring \
    --key=data-encryption-key \
    --ciphertext-file=secrets.txt.enc \
    --plaintext-file=secrets-decrypted.txt

Cifrado de disco (Linux - LUKS):
# Cifrar partición (CUIDADO: borra datos)
sudo cryptsetup luksFormat /dev/sdb1

# Abrir partición cifrada
sudo cryptsetup luksOpen /dev/sdb1 encrypted_data

# Formatear y montar
sudo mkfs.ext4 /dev/mapper/encrypted_data
sudo mount /dev/mapper/encrypted_data /mnt/secure

# Cerrar al terminar
sudo umount /mnt/secure
sudo cryptsetup luksClose encrypted_data

Cifrado de disco (Windows - BitLocker):
# Habilitar BitLocker en C:
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector

# Hacer backup de recovery key
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].KeyProtectorId

Tokenización de Datos de Pago
Usar Stripe para PCI compliance:
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Frontend: crear token de tarjeta (nunca enviar datos completos)
// Stripe.js se encarga de esto en el navegador

// Backend: procesar pago con token
async function processPayment(amount, tokenId) {
  const charge = await stripe.charges.create({
    amount: amount * 100, // centavos
    currency: 'eur',
    source: tokenId,  // Token, no datos de tarjeta
    description: 'Purchase from app'
  });
  
  // Guardar solo último 4 dígitos y brand
  return {
    transactionId: charge.id,
    last4: charge.source.last4,
    brand: charge.source.brand
  };
}

# Kit de Seguridad - Continuación SDLC Seguro

## SAST - Análisis Estático (Continuación)

### Semgrep - Configuración avanzada

```bash
# Instalar
pip install semgrep

# Ejecutar localmente
semgrep --config=auto src/

# Con reglas específicas
semgrep --config=p/owasp-top-ten --config=p/jwt src/

# Generar reporte JSON
semgrep --config=auto --json -o semgrep-report.json src/
```

**Archivo .semgrep.yml - Reglas personalizadas:**

```yaml
rules:
  - id: hardcoded-secret
    pattern: |
      password = "..."
    message: "Contraseña hardcodeada detectada"
    severity: ERROR
    languages: [python, javascript, java]

  - id: sql-injection
    pattern: |
      execute("SELECT * FROM users WHERE id = " + $VAR)
    message: "Posible SQL injection"
    severity: ERROR

  - id: weak-crypto
    pattern: |
      crypto.createHash('md5')
    message: "Algoritmo de hash débil (MD5)"
    severity: WARNING
    languages: [javascript]
    
  - id: jwt-no-verify
    pattern: |
      jwt.decode($TOKEN, {verify: false})
    message: "JWT sin verificación de firma"
    severity: ERROR
    languages: [javascript]
```

### SonarQube

```bash
# Docker con SonarQube
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  sonarqube:latest

# Instalar scanner
npm install -g sonarqube-scanner

# Configurar proyecto - sonar-project.properties
sonar.projectKey=fintech-app
sonar.sources=src
sonar.exclusions=**/node_modules/**,**/*.test.js
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.host.url=http://localhost:9000

# Ejecutar análisis
sonar-scanner -Dsonar.login=YOUR_TOKEN
```

---

## DAST - Análisis Dinámico

### OWASP ZAP

```bash
# Ejecutar ZAP baseline scan en Docker
docker run -u zap -p 8080:8080 \
  -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable \
  zap-baseline.py \
  -t https://api.example.com \
  -r zap-report.html

# Scan completo (más agresivo, usar en staging)
docker run -u zap \
  owasp/zap2docker-stable \
  zap-full-scan.py \
  -t https://api.example.com \
  -r zap-full-report.html

# Con autenticación
docker run -u zap \
  owasp/zap2docker-stable \
  zap-baseline.py \
  -t https://api.example.com \
  -c zap-config.conf \
  -r zap-auth-report.html
```

**Archivo zap-config.conf:**

```
# Configuración de autenticación
auth.loginurl=https://api.example.com/login
auth.username=testuser
auth.password=testpass
auth.username_field=email
auth.password_field=password
auth.submit_field=submit
```

### Burp Suite (proceso manual)

**Pasos:**
1. Configurar proxy en navegador: 127.0.0.1:8080
2. Abrir Burp Suite → Proxy → Intercept
3. Navegar la aplicación y capturar requests
4. Usar Repeater para modificar y reenviar requests
5. Usar Intruder para fuzzing de parámetros
6. Analizar respuestas en busca de información sensible
7. Revisar Scanner results para vulnerabilidades automáticas

### Nuclei (scanning automatizado)

```bash
# Instalar
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Actualizar templates
nuclei -update-templates

# Scan básico
nuclei -u https://api.example.com

# Scan con severidad alta/crítica solamente
nuclei -u https://api.example.com -severity critical,high

# Con templates específicos
nuclei -u https://api.example.com -t cves/ -t vulnerabilities/

# Múltiples targets desde archivo
nuclei -list targets.txt -severity high,critical -o results.txt

# Con rate limiting para no saturar
nuclei -u https://api.example.com -rate-limit 10
```

---

## SCA - Análisis de Dependencias

### npm audit

```bash
# Verificar vulnerabilidades
npm audit

# Ver detalles en formato JSON
npm audit --json

# Generar reporte completo
npm audit --json > audit-report.json

# Intentar fix automático (solo versiones compatibles)
npm audit fix

# Fix forzado - CUIDADO: puede romper dependencias
npm audit fix --force

# Ver solo vulnerabilidades críticas/altas
npm audit --audit-level=high
```

### Snyk

```bash
# Instalar
npm install -g snyk

# Autenticar (abre navegador)
snyk auth

# Test de vulnerabilidades
snyk test

# Test con reporte JSON
snyk test --json > snyk-report.json

# Monitor proyecto (envía a dashboard de Snyk)
snyk monitor

# Test con severidad específica
snyk test --severity-threshold=high

# Ignorar vulnerabilidades específicas
snyk ignore --id=SNYK-JS-MINIMIST-559764

# Test de imagen Docker
snyk test --docker node:18-alpine

# Fix automático de vulnerabilidades
snyk fix
```

**Archivo .snyk para configuración:**

```yaml
# Snyk configuration file
version: v1.22.0
ignore:
  SNYK-JS-MINIMIST-559764:
    - '*':
        reason: No fix available, low risk in our context
        expires: 2025-12-31T00:00:00.000Z
patch: {}
```

### Dependabot (GitHub)

**Archivo .github/dependabot.yml:**

```yaml
version: 2
updates:
  # npm dependencies
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    commit-message:
      prefix: "chore"
      include: "scope"

  # Docker dependencies
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    
  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### OWASP Dependency-Check

```bash
# Descargar (una vez)
wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip
unzip dependency-check-8.4.0-release.zip

# Ejecutar análisis
./dependency-check/bin/dependency-check.sh \
  --project "Fintech App" \
  --scan ./src \
  --out ./reports \
  --format HTML

# Con supresión de falsos positivos
./dependency-check/bin/dependency-check.sh \
  --project "Fintech App" \
  --scan ./src \
  --out ./reports \
  --suppression suppression.xml

# Actualizar base de datos NVD
./dependency-check/bin/dependency-check.sh --updateonly
```

**Archivo suppression.xml:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <notes>False positive - not applicable to our usage</notes>
        <cve>CVE-2021-12345</cve>
    </suppress>
</suppressions>
```

---

## Secret Scanning

### GitLeaks

```bash
# Instalar
brew install gitleaks
# o
docker pull zricethezav/gitleaks:latest

# Escanear repo actual
gitleaks detect --source . --verbose

# Escanear commits específicos
gitleaks detect --source . --log-opts="--since=2024-01-01"

# Con configuración personalizada
gitleaks detect --config .gitleaks.toml

# Escanear sin cache
gitleaks detect --no-cache

# Generar reporte JSON
gitleaks detect --report-path gitleaks-report.json --report-format json
```

**Archivo .gitleaks.toml:**

```toml
title = "Gitleaks Config for Fintech App"

[extend]
useDefault = true

[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "credentials"]

[[rules]]
id = "stripe-api-key"
description = "Stripe API Key"
regex = '''sk_live_[0-9a-zA-Z]{24}'''
tags = ["stripe", "payment"]

[[rules]]
id = "jwt-secret"
description = "JWT Secret"
regex = '''jwt[_-]?secret["\']?\s*[:=]\s*["\'][^"\']{20,}["\']'''
tags = ["jwt", "authentication"]

[allowlist]
description = "Allowlist"
paths = [
  '''node_modules/''',
  '''\.git/''',
  '''package-lock\.json''',
]
```

### TruffleHog

```bash
# Instalar
pip install truffleHog

# Escanear repo
trufflehog git https://github.com/yourorg/yourrepo --json

# Escanear repo local
trufflehog filesystem . --json

# Solo alta entropía
trufflehog git https://github.com/yourorg/yourrepo --entropy

# Con verificación de secrets activos
trufflehog git https://github.com/yourorg/yourrepo --verify

# Escanear Docker image
trufflehog docker --image myapp:latest
```

### git-secrets (AWS)

```bash
# Instalar
brew install git-secrets

# Configurar en repo
cd /path/to/repo
git secrets --install

# Agregar patrones AWS
git secrets --register-aws

# Agregar patrones personalizados
git secrets --add 'password\s*=\s*.+'
git secrets --add 'api[_-]?key\s*=\s*.+'

# Escanear historial completo
git secrets --scan-history

# Escanear antes de commit (hook automático)
# Ya configurado con --install
```

---

## Pipeline CI/CD Seguro

### GitHub Actions - Workflow de Seguridad

**Archivo .github/workflows/security.yml:**

```yaml
name: Security Checks

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  secret-scanning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: GitLeaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  dependency-scanning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: npm audit
        run: npm audit --audit-level=high
        continue-on-error: true
      
      - name: Snyk Test
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

  sast-scanning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/security-audit
      
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

  container-scanning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  dast-scanning:
    runs-on: ubuntu-latest
    needs: [sast-scanning, dependency-scanning]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to staging
        run: |
          # Script de deploy a staging
          ./deploy-staging.sh
      
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'https://staging.example.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

  security-report:
    runs-on: ubuntu-latest
    needs: [secret-scanning, dependency-scanning, sast-scanning, container-scanning]
    if: always()
    steps:
      - name: Consolidate reports
        run: |
          echo "Security scan completed"
          echo "Check individual job results"
      
      - name: Notify team
        uses: 8398a7/action-slack@v3
        if: failure()
        with:
          status: ${{ job.status }}
          text: 'Security scan failed - check GitHub Actions'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### GitLab CI/CD

**Archivo .gitlab-ci.yml:**

```yaml
stages:
  - test
  - security
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"

# Template para seguridad
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

unit-tests:
  stage: test
  image: node:18-alpine
  script:
    - npm ci
    - npm run test:coverage
  coverage: '/Statements\s*:\s*(\d+\.\d+)%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

semgrep-sast:
  stage: security
  image: returntocorp/semgrep
  script:
    - semgrep --config=auto --json -o semgrep-report.json src/
  artifacts:
    reports:
      sast: semgrep-report.json
    expire_in: 1 week
  allow_failure: true

npm-audit:
  stage: security
  image: node:18-alpine
  script:
    - npm ci
    - npm audit --json > npm-audit.json || true
    - npm audit --audit-level=high
  artifacts:
    paths:
      - npm-audit.json
    expire_in: 1 week
  allow_failure: false

snyk-test:
  stage: security
  image: node:18-alpine
  before_script:
    - npm install -g snyk
    - snyk auth $SNYK_TOKEN
  script:
    - npm ci
    - snyk test --severity-threshold=high --json > snyk-report.json
  artifacts:
    paths:
      - snyk-report.json
    expire_in: 1 week
  allow_failure: true

container-scanning:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  variables:
    DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy image --severity HIGH,CRITICAL $DOCKER_IMAGE
  allow_failure: true

zap-dast:
  stage: security
  image: owasp/zap2docker-stable
  script:
    - zap-baseline.py -t $STAGING_URL -r zap-report.html
  artifacts:
    paths:
      - zap-report.html
    expire_in: 1 week
  only:
    - main
  allow_failure: true

deploy-production:
  stage: deploy
  script:
    - echo "Deploying to production"
    - ./deploy-prod.sh
  only:
    - main
  when: manual
  needs: 
    - semgrep-sast
    - npm-audit
    - container-scanning
```

---

## Monitoreo y Detección

### ELK Stack (Elasticsearch, Logstash, Kibana)

**docker-compose.yml para ELK:**

```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    networks:
      - elk

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    container_name: logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
    ports:
      - "5044:5044"
      - "9600:9600"
    environment:
      - "LS_JAVA_OPTS=-Xms512m -Xmx512m"
    networks:
      - elk
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    container_name: kibana
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=changeme
    networks:
      - elk
    depends_on:
      - elasticsearch

volumes:
  esdata:
    driver: local

networks:
  elk:
    driver: bridge
```

**Logstash pipeline - logstash/pipeline/logstash.conf:**

```conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  # Parse JSON logs
  if [message] =~ /^\{.*\}$/ {
    json {
      source => "message"
    }
  }
  
  # Grok para logs de Nginx
  if [type] == "nginx-access" {
    grok {
      match => { "message" => "%{IPORHOST:remote_addr} - %{DATA:remote_user} \[%{HTTPDATE:time_local}\] \"%{WORD:request_method} %{DATA:request_uri} HTTP/%{NUMBER:http_version}\" %{NUMBER:status} %{NUMBER:body_bytes_sent} \"%{DATA:http_referer}\" \"%{DATA:http_user_agent}\"" }
    }
    
    # Detectar ataques comunes
    if [request_uri] =~ /(\.\.|\/etc\/passwd|<script|UNION\s+SELECT|exec\()/i {
      mutate {
        add_tag => ["potential_attack"]
      }
    }
  }
  
  # Detección de intentos de login fallidos
  if [message] =~ /Failed password|authentication failure|Invalid user/ {
    mutate {
      add_tag => ["failed_login"]
      add_field => { "alert_level" => "warning" }
    }
  }
  
  # Geolocate IPs
  geoip {
    source => "remote_addr"
    target => "geoip"
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "logs-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "changeme"
  }
  
  # Output condicional para alertas
  if "potential_attack" in [tags] or "failed_login" in [tags] {
    file {
      path => "/var/log/security-alerts.log"
      codec => json_lines
    }
  }
  
  stdout {
    codec => rubydebug
  }
}
```

### Filebeat para envío de logs

**filebeat.yml:**

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log
    fields:
      type: nginx-access
    fields_under_root: true

  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/secure
    fields:
      type: system-auth
    fields_under_root: true

  - type: log
    enabled: true
    paths:
      - /var/log/app/*.log
    json.keys_under_root: true
    json.add_error_key: true

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~

output.logstash:
  hosts: ["logstash:5044"]
  
# Si prefieres enviar directo a Elasticsearch:
# output.elasticsearch:
#   hosts: ["elasticsearch:9200"]
#   username: "elastic"
#   password: "changeme"
#   index: "filebeat-%{+yyyy.MM.dd}"

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
```

### Prometheus + Grafana para métricas

**docker-compose.yml para monitoreo:**

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
    ports:
      - "9090:9090"
    networks:
      - monitoring
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    ports:
      - "3000:3000"
    networks:
      - monitoring
    depends_on:
      - prometheus
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    ports:
      - "9100:9100"
    networks:
      - monitoring
    restart: unless-stopped

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    ports:
      - "9093:9093"
    networks:
      - monitoring
    restart: unless-stopped

volumes:
  prometheus_data:
  grafana_data:

networks:
  monitoring:
    driver: bridge
```

**prometheus/prometheus.yml:**

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'fintech-prod'
    environment: 'production'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

rule_files:
  - 'alerts/*.yml'

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'api-backend'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['api:8080']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '([^:]+)(:[0-9]+)?'
        replacement: '${1}'

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
```

**prometheus/alerts/security-alerts.yml:**

```yaml
groups:
  - name: security_alerts
    interval: 30s
    rules:
      - alert: HighFailedLoginRate
        expr: rate(failed_login_attempts_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "High rate of failed login attempts"
          description: "{{ $value }} failed login attempts per second in the last 5 minutes on {{ $labels.instance }}"

      - alert: UnauthorizedAccessAttempt
        expr: http_requests_total{status="401"} > 100
        for: 5m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "Multiple unauthorized access attempts"
          description: "{{ $value }} unauthorized (401) requests detected"

      - alert: SQLInjectionAttempt
        expr: increase(sql_injection_attempts_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
          category: security
        annotations:
          summary: "SQL Injection attempt detected"
          description: "Possible SQL injection attack detected from {{ $labels.source_ip }}"

      - alert: AbnormalTrafficVolume
        expr: rate(http_requests_total[5m]) > 1000
        for: 5m
        labels:
          severity: warning
          category: performance
        annotations:
          summary: "Abnormal traffic volume detected"
          description: "Traffic rate of {{ $value }} req/s is abnormally high - possible DDoS"

      - alert: CriticalServiceDown
        expr: up{job="api-backend"} == 0
        for: 1m
        labels:
          severity: critical
          category: availability
        annotations:
          summary: "Critical service is down"
          description: "{{ $labels.job }} on {{ $labels.instance }} has been down for more than 1 minute"

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
        for: 5m
        labels:
          severity: warning
          category: resources
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 90% on {{ $labels.instance }}"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) < 0.1
        for: 5m
        labels:
          severity: warning
          category: resources
        annotations:
          summary: "Low disk space"
          description: "Less than 10% disk space remaining on {{ $labels.instance }}"
```

**alertmanager/alertmanager.yml:**

```yaml
global:
  resolve_timeout: 5m
  slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      continue: true
    
    - match:
        category: security
      receiver: 'security-team'
      continue: true

receivers:
  - name: 'default'
    slack_configs:
      - channel: '#alerts'
        title: 'Alert: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

  - name:

