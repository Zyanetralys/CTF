# CTF Captain Linux
<img src="https://tacticalgearjunkie.com/cdn/shop/products/tacticalpenguinnewsticker-423371.jpg" width="300"/>

## 1 Conectarse a la máquina del examen

Conectarse usando SSH con el usuario y la contraseña del examen.
Comando: "ssh captain@<IP> -p 22"
Password: shadow

## 2 Home

Ir al directorio home de captain: "cd /home/captain"
Listar todos los archivos: "ls -a"
Archivos importantes:

emailpass.txt

moment.txt

files/

favorite_movie.txt (archivo protegido)

## 3 Explorar directorios y archivos ocultos

Listar todos los archivos en la carpeta files: "ls -la files"
Leer el archivo oculto: "cat files/.favorite_country.txt"

## 4 Contar palabras de un archivo

Contar palabras del archivo moment.txt: "wc -w moment.txt"
Salida esperada: 367

## 5 Mostrar última línea de un archivo

Mostrar la última línea de emailpass.txt: "tail -n 1 emailpass.txt"

## 6 Buscar información específica en un archivo

Buscar el email whoami@securemail.hv
 en emailpass.txt: "grep whoami@securemail.hv
 emailpass.txt"

## 7 Localizar la ruta de un comando

Localizar el comando hello: "which hello"

## 8 Buscar un archivo de configuración en todo el sistema

Buscar database.conf: "find / -name database.conf 2>/dev/null"

## 9 Ver permisos de un archivo protegido (favorite_movie.txt)

Ver permisos del archivo: "ls -l favorite_movie.txt"
Problema: El archivo tiene permisos 0000 y no puede leerse directamente.
Intentar leer el archivo: "cat favorite_movie.txt" → Permission denied

Solución

El archivo tiene permisos 0000, propietario captain, tamaño 13 bytes.

### Método 1: Cambiar permisos
Dar permisos de lectura al propietario: "chmod 400 /home/captain/favorite_movie.txt"
Verificar: "ls -l /home/captain/favorite_movie.txt"
Leer el archivo: "cat /home/captain/favorite_movie.txt"

### Método 2: Copiar archivo si chmod no funciona
Copiar el archivo: "cp /home/captain/favorite_movie.txt /tmp/movie_copy.txt"
Leer la copia: "cat /tmp/movie_copy.txt"

### Método 3: Usar dd para bypass de permisos
Usar dd: "dd if=/home/captain/favorite_movie.txt of=/tmp/movie_output.txt 2>/dev/null"
Leer salida: "cat /tmp/movie_output.txt"

### Método 4: Verificar inodos y links duros
Ver información del inodo: "stat /home/captain/favorite_movie.txt"
Buscar links duros: "find / -inum <NUMERO_INODO> 2>/dev/null"

### Acción
Cambiar permisos: "chmod 644 /home/captain/favorite_movie.txt"
Leer archivo: "cat /home/captain/favorite_movie.txt"
Si falla chmod:
Copiar archivo: "cp /home/captain/favorite_movie.txt /tmp/readable_movie.txt"
Leer copia: "cat /tmp/readable_movie.txt"

## 10 Consultar UID de un usuario

Consultar UID de specter: "id -u specter"
Salida esperada: 1001

## 11 Archivos y directorios de interés

files/.favorite_country.txt → contiene el país favorito

moment.txt → contar palabras

emailpass.txt → contiene pares email:password

favorite_movie.txt → protegido

=========================

---

# PARTE 2 CTF

Conexión a la máquina

IP: 172.20.16.137

Usuario: Administrator

Contraseña: password123

Instrucción: Conectar vía RDP usando estas credenciales

Información general del sistema

## 2.1 Usuarios

Comando: "net user"

Respuesta del examen: "Becket"

## 2.2 Carpetas y permisos

Navegar a la carpeta: "C:\Users\Administrator\Desktop"

Comando: "icacls myprograms"

## 2.3 Servicios

Consultar estado del servicio: "sc query StrikerEureka"

Respuesta exacta del examen:
"SERVICE_NAME: StrikerEureka
TYPE : 10 WIN32_OWN_PROCESS
STATE : 1 STOPPED
WIN32_EXIT_CODE : 1077 (0x435)
SERVICE_EXIT_CODE : 0 (0x0)
CHECKPOINT : 0x0
WAIT_HINT : 0x0"

## 2.4 Procesos en ejecución

Comando: "tasklist"

Resultado: listar procesos activos como explorer.exe, cmd.exe, svchost.exe…

## 2.5 Programas al inicio

Carpeta Startup de Administrator: "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

Programas detectados: jaeger, windows security notifications

## 2.6 Firewall y programas inusuales

Comando para ver reglas firewall: "netsh advfirewall firewall show rule name=all"

Para detectar programas permitidos con nombres inusuales, filtrar la salida.

Reglas importantes (nc): Enabled: Yes, Direction: In, Profiles: Private,Public, Protocol: TCP/UDP, LocalPort: Any, Action: Allow

Abrir puertos en Windows

Comandos para abrir puertos 5000 y 4444 en perfil Domain:
"netsh advfirewall firewall add rule name="nc-domain" dir=in action=allow protocol=TCP localport=5000 profile=domain"
"netsh advfirewall firewall add rule name="nc-domain" dir=in action=allow protocol=TCP localport=4444 profile=domain"

Netcat / Listener en Windows

Problema: Comando "nc" no reconocido.

Solución PowerShell listener TCP:
"powershell $listener = [System.Net.Sockets.TcpListener]5000; $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); $reader = New-Object System.IO.StreamReader($stream); while(($line = $reader.ReadLine()) -ne $null) { Write-Output $line }"

Conectar desde otra máquina:
"$client = New-Object System.Net.Sockets.TcpClient("172.20.16.137",5000); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $writer.AutoFlush = $true; $writer.WriteLine("Mensaje de prueba")"

Conexión y verificación de puertos

Confirmar que firewall y listener están activos.

Conectar desde cliente remoto usando PowerShell o Netcat (Linux).

Enviar mensaje de prueba y confirmar recepción.

## Comandos esenciales Windows

Ver reglas firewall: "netsh advfirewall firewall show rule name=(nc)"

Añadir regla firewall: "netsh advfirewall firewall add rule name="nc-domain" dir=in action=allow protocol=TCP localport=PORT profile=PROFILE"

Ver puertos escuchando: "netstat -an | find "PORT""

Ping y conectividad: "ping IP_OBJETIVO"

Listar usuarios: "net user"

Listar permisos: "icacls RUTA_CARPETA"

Listar procesos: "tasklist"

Consultar estado de servicio: "sc query NOMBRE_SERVICIO"

==============

---
