# Telnet Recon

## MISIÓN: Reconocimiento, acceso y análisis de la máquina Telnet Arrow
## NIVEL: Básico/Intermedio

## CONECTIVIDAD

Objetivo: Confirmar que la máquina está activa.

Comando: "ping -c 4 172.20.4.28"

Resultado esperado: 0% pérdida de paquetes.

Contingencias: pérdida de paquetes indica problemas de red o firewall.

## PUERTOS Y SERVICIOS

Objetivo: Identificar puertos abiertos y servicios activos.

Comandos:

"nc -vz 172.20.4.28 23" → Verificar puerto 23 rápido.

"nmap -p 23 172.20.4.28" → Confirmar puerto y servicio.

"nmap -sV 172.20.4.28" → Detectar banner y versión del servicio.

Puerto abierto confirmado: 23

Servicio activo: Telnet

Banner recibido:
Hey you, you're trying to connect to me.
You should always try default credentials like root:root
it's just beginning _
arrow login:

## CREDENCIALES Y ACCESO

Usuario: root

Contraseña: root

Posibles alternativas: admin:admin, guest:guest

Comando de conexión: "telnet 172.20.4.28 23"

Recomendación: ingresar con root:root y registrar banner completo.

## ENTORNO TRAS CONEXIÓN

Directorio de trabajo inicial: /root

Comandos de reconocimiento:

"pwd" → Ver directorio actual.

"ls -la" → Listar archivos y permisos, incluyendo ocultos.

"uname -a" → Información del kernel y arquitectura.

"cat /etc/os-release" → Distribución Linux y versión.

"cat /etc/passwd" → Listado de usuarios del sistema.

"ps aux" → Procesos activos y sus detalles.

"netstat -tulnp" → Puertos y servicios escuchando en TCP/UDP.

## USUARIOS Y PRIVILEGIOS

Objetivo: Identificar usuarios y privilegios.

Comandos:

"cat /etc/passwd" → Revisar usuarios locales.

"id [usuario]" → Ver UID, GID y grupos de cualquier usuario.

"whoami" → Confirmar usuario actual.

ARCHIVOS Y RUTAS DE INTERÉS

Objetivo: Buscar información crítica y pistas de CTF.

Comandos:

"ls -la /root" → Archivos ocultos o scripts de práctica.

"find / -name '*.txt' 2>/dev/null" → Archivos de texto en todo el sistema.

"find / -name '*.conf' 2>/dev/null" → Archivos de configuración.

"find / -name '*.bak' 2>/dev/null" → Copias de seguridad.

## PROCESOS Y SERVICIOS ADICIONALES

Objetivo: Identificar servicios y procesos activos que puedan dar pistas.

Comandos:

"ps aux" → Procesos activos.

"netstat -tulnp" → Puertos y servicios activos, con PID.

"lsof -i" → Archivos abiertos relacionados con red.

## INFORMACIÓN DEL SISTEMA

Objetivo: Conocer el entorno y posibles vulnerabilidades.

Comandos:

"uname -a" → Kernel y arquitectura.

"cat /etc/os-release" → Distribución Linux.

"hostname" → Nombre de la máquina.

"uptime" → Tiempo activo y carga del sistema.

## REGISTRO

Registrar cada comando y su salida en diario de misión.

Documentar banners, archivos, usuarios, procesos y directorios.

Registrar credenciales adicionales encontradas.

Mantener consistencia para reportes de CTF.

## RIESGOS Y CONSIDERACIONES

Telnet sin cifrado → tráfico visible en red.

Acceso root con credenciales por defecto → vulnerabilidad crítica en entornos reales.

No modificar archivos críticos del sistema.

Mantener registro de cada acción.

## RESUMEN

Máquina accesible: 172.20.4.28

Puerto abierto: 23

Servicio activo: Telnet

Credenciales por defecto: root:root

Directorio de trabajo inicial: /root

Banner indica entorno de práctica / laboratorio CTF

Rutas de exploración: archivos ocultos, usuarios adicionales, procesos y puertos internos

Comandos principales para explorar: "pwd", "ls -la", "cat /etc/passwd", "ps aux", "netstat -tulnp", "find / -name '.txt' 2>/dev/null", "find / -name '.conf' 2>/dev/null", "find / -name '*.bak' 2>/dev/null"
