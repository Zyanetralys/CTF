# CTF Windows RDC

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

---
