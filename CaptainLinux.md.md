# CTF Captain Linux
<img src="https://pbs.twimg.com/profile_images/824801278614204416/x9uWuwPm_400x400.jpg" width="300"/>

## 1 Conectarse a la máquina del examen

Conectarse usando SSH con el usuario y la contraseña del examen.
Comando: "ssh captain@<IP_DEL_EXAMEN> -p 22"
Password: shadow
Reemplaza <IP_DEL_EXAMEN> con la IP que te den.

## 2 Navegar al directorio home del usuario

Ir al directorio home de captain: "cd /home/captain"
Listar todos los archivos: "ls -a"
Archivos importantes:

emailpass.txt

moment.txt

files/

favorite_movie.txt (archivo protegido, no legible directamente)

## 3 Explorar directorios y archivos ocultos

Listar todos los archivos en la carpeta files: "ls -la files"
Leer el archivo oculto: "cat files/.favorite_country.txt"
Salida esperada: italy

## 4 Contar palabras de un archivo

Contar palabras del archivo moment.txt: "wc -w moment.txt"
Salida esperada: 367

## 5 Mostrar última línea de un archivo

Mostrar la última línea de emailpass.txt: "tail -n 1 emailpass.txt"
Salida esperada: michel@securemail.hv
:pf8Dkpfw24

## 6 Buscar información específica en un archivo

Buscar el email whoami@securemail.hv
 en emailpass.txt: "grep whoami@securemail.hv
 emailpass.txt"
Salida esperada: whoami@securemail.hv
:DeU8CHcpa2

## 7 Localizar la ruta de un comando

Localizar el comando hello: "which hello"
Salida esperada: /usr/bin/hello

## 8 Buscar un archivo de configuración en todo el sistema

Buscar database.conf: "find / -name database.conf 2>/dev/null"
Salida esperada: /etc/config/database/database.conf

## 9 Ver permisos de un archivo protegido (favorite_movie.txt)

Ver permisos del archivo: "ls -l favorite_movie.txt"
Problema: El archivo tiene permisos 0000 y no puede leerse directamente.
Salida típica: ---------- 1 captain captain 13 Mar 23 2024 favorite_movie.txt
Intentar leer el archivo: "cat favorite_movie.txt" → Permission denied

Solución

El archivo tiene permisos 0000, propietario captain, tamaño 13 bytes.

### Método 1: Cambiar permisos
Dar permisos de lectura al propietario: "chmod 400 /home/captain/favorite_movie.txt"
Verificar: "ls -l /home/captain/favorite_movie.txt"
Leer el archivo: "cat /home/captain/favorite_movie.txt"
Salida: interestellar

### Método 2: Copiar archivo si chmod no funciona
Copiar el archivo: "cp /home/captain/favorite_movie.txt /tmp/movie_copy.txt"
Leer la copia: "cat /tmp/movie_copy.txt"

### Método 3: Usar dd para bypass de permisos
Usar dd: "dd if=/home/captain/favorite_movie.txt of=/tmp/movie_output.txt 2>/dev/null"
Leer salida: "cat /tmp/movie_output.txt"

### Método 4: Verificar inodos y links duros
Ver información del inodo: "stat /home/captain/favorite_movie.txt"
Buscar links duros: "find / -inum <NUMERO_INODO> 2>/dev/null"

### Resumen
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

favorite_movie.txt → protegido, contenido: interestellar
