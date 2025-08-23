# Query Gate

## FASE 1 – RECONOCIMIENTO
Se realizó un escaneo de puertos con el comando "nmap -sV <IP_objetivo>".
Resultado: puerto abierto 3306, servicio mysql.
Evaluación: La máquina es accesible por MySQL, sin bloqueos de firewall.

## FASE 2 – ACCESO AL SERVICIO
Usuario predeterminado con privilegios: "root".
Parámetro para especificar la máquina objetivo: "-h".
Comando de conexión: "mysql -h <IP_objetivo> -u root -p"
Nota: En este ejercicio, no se requiere contraseña, por lo que se omite el parámetro "-p". La conexión fue exitosa.

## FASE 3 – ENUMERACIÓN DE BASES DE DATOS
Comando utilizado: "SHOW DATABASES;"
Resultado: 5 bases de datos detectadas.

## FASE 4 – SELECCIÓN DE BASE DE DATOS
Base de interés: "detective_inspector"
Comando para seleccionar la base: "USE detective_inspector;"

## FASE 5 – IDENTIFICACIÓN DE TABLAS
Comando para listar tablas: "SHOW TABLES;"
Resultado: tabla identificada como "hacker_list"

## FASE 6 – EXTRACCIÓN DE INFORMACIÓN
Comando para obtener registros: "SELECT * FROM hacker_list;"
Resultado: nickname del hacker ético: "h4ckv1s3r"

## CONCLUSIONES
Operación exitosa.
Se identificó el puerto MySQL abierto, se conectó con usuario root, se enumeraron bases de datos, se seleccionó la base correcta, se identificó la tabla relevante y se extrajo el registro crítico.
Información obtenida cumple con los objetivos de la misión.
