# Misión Arrow – Telnet Recon

Objetivo: Acceder a la máquina Telnet 172.20.4.28 y recopilar información inicial.

1️⃣ Verificación de conectividad
Comando: "ping -c 4 172.20.4.28"
Resultado esperado: 0% pérdida de paquetes, máquina viva.

2️⃣ Escaneo de puerto Telnet
Comando rápido: "nc -vz 172.20.4.28 23" → verifica puerto 23 abierto.
Comando detallado: "nmap -p 23 172.20.4.28" → confirma puerto y servicio.
Comando avanzado: "nmap -sV 172.20.4.28" → detecta versión y banner del servicio.

Puerto abierto confirmado: 23
Servicio activo: Telnet

3️⃣ Conexión Telnet
Comando: "telnet 172.20.4.28 23"
Banner recibido:
Hey you, you're trying to connect to me.
You should always try default credentials like root:root
it's just beginning _
arrow login:

4️⃣ Login
Usuario: "root"
Contraseña: "root"
Prompt tras login: máquina lista para comandos.

5️⃣ Reconocimiento básico
Ver directorio actual: "pwd" → normalmente /root
Listar archivos y permisos: "ls -la"
Información del sistema: "uname -a" / "cat /etc/os-release"
Revisar usuarios: "cat /etc/passwd"
Procesos activos: "ps aux"
Puertos abiertos: "netstat -tulnp"

6️⃣ Notas tácticas
Registrar todo en diario de misión.
No alterar archivos críticos.
Observar banners y pistas para fases posteriores del CTF.
Comando para verificar conectividad: "ping -c 4 172.20.4.28"
Comando para verificar puerto: "nc -vz 172.20.4.28 23"
Comando para detectar servicio y versión: "nmap -sV 172.20.4.28"
Comando para listar archivos: "ls -la"
Comando para ver directorio actual: "pwd"
Comando para ver usuarios: "cat /etc/passwd"
