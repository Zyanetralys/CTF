# CTF Hackviser

1 Conectarse a la máquina del examen

ssh captain@<IP_DEL_EXAMEN> -p 22

Password: shadow

Reemplaza <IP_DEL_EXAMEN> con la IP que te den.

2 Navegar al directorio home del usuario

cd /home/captain
ls -a
Archivos importantes:

emailpass.txt

moment.txt

files/

favorite_movie.txt (archivo protegido, no legible)

3 Explorar directorios y archivos ocultos

ls -la files
cat files/.favorite_country.txt

4 Contar palabras de un archivo

wc -w moment.txt

5 Mostrar última línea de un archivo

tail -n 1 emailpass.txt

6 Buscar información específica en un archivo

grep whoami@securemail.hv
 emailpass.txt

7 Localizar la ruta de un comando

which hello

8 Buscar un archivo de configuración en todo el sistema

find / -name database.conf 2>/dev/null

9 Ver permisos de un archivo

ls -l favorite_movie.txt

Resultado típico: Permission denied

Hackviser bloquea acceso directo; la respuesta debe obtenerse del material oficial del examen.

10 Consultar UID de un usuario

id -u specter

11 Archivos y directorios de interés

files/.favorite_country.txt → contiene el país favorito

moment.txt → contar palabras

emailpass.txt → contiene pares email:password

favorite_movie.txt → protegido, respuesta en material del examen
