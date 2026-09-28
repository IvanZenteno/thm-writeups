# Ejercicio a Ciegas #03 — Redis sin Autenticación → RCE vía SSH

> Práctica de metodología sin guía. Vector distinto a los ejercicios #01 y
> #02 (aquí no es una vulnerabilidad web, sino un servicio de base de
> datos mal configurado). Mismo formato: escenario + decisión con
> opciones, basado en una sesión real de razonamiento guiado.

## Cómo usar este ejercicio

Igual que los anteriores: lee el resultado, responde tú primero en texto
libre, luego revisa las opciones, y abre la respuesta para comparar el
*porqué*.

---

## Escenario inicial

```
Nmap scan report for 10.10.x.x
Host is up (0.02s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu
80/tcp   open  http     nginx 1.18.0
3306/tcp open  mysql    MySQL 8.0.32
6379/tcp open  redis    Redis key-value store
```

No sabes nada más.

### Decisión 1 — ¿Cómo evalúas esta combinación de puertos?

**A.** SSH, MySQL y Redis son básicamente el mismo tipo de superficie — servicios de acceso donde el único vector es fuerza bruta.
**B.** El puerto 80 es el más prometedor por default; los demás servicios, al tener versiones recientes, solo se revisan si el 80 no da resultado.
**C.** El puerto 80 merece atención, pero Redis (6379) no debería descartarse ni agruparse con SSH/MySQL — su modelo de seguridad por defecto es distinto.
**D.** Con versiones tan actualizadas en todos los servicios, ninguno es prometedor — conviene escanear puertos UDP en su lugar.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: C**

- **A comete un error de categorización:** agrupar Redis con SSH/MySQL
  asume que todos requieren "adivinar una credencial que existe" — pero
  Redis, en instalaciones por defecto sin configuración adicional, **no
  pide ninguna autenticación en absoluto**. No es fuerza bruta, es
  ausencia total de control de acceso — una categoría de riesgo distinta
  y generalmente más grave.
- **B no es incorrecta en priorizar el 80 primero**, pero relega a Redis
  a "solo si falla lo demás", cuando en realidad merece revisión con
  prioridad similar por la razón de A.
- **D generaliza mal:** que las versiones sean recientes reduce la
  probabilidad de un CVE de *software*, pero no dice nada sobre errores
  de *configuración* (como Redis expuesto sin auth), que son
  independientes de qué tan actualizado esté el binario.

**Dato clave para llevarte:** Redis, en su configuración por defecto (sin
que nadie la haya asegurado explícitamente), no requiere usuario ni
contraseña para conectarse y ejecutar comandos administrativos completos.

</details>

---

## Decisión 2 — Confirmando el hallazgo

Corres `redis-cli -h <IP>` y te conectas sin pedir ninguna credencial.
Tienes acceso completo a comandos de Redis.

### ¿Qué comandos corres primero para reconocer el terreno?

**A.** `FLUSHALL` para limpiar la base y evitar interferencias.
**B.** `INFO` y `CONFIG GET *` para entender la configuración actual del servidor.
**C.** Directamente `SET`/`SAVE` con un payload, sin revisar configuración previa.
**D.** `KEYS *` para ver qué datos de aplicación existen, ignorando la configuración del servidor.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A es destructivo e innecesario** — borrar datos de la base no aporta
  nada a la explotación y podría alertar a cualquier monitoreo activo.
- **C se salta un paso crítico de reconocimiento** — sin saber la
  configuración actual (especialmente `dir` y `dbfilename`), no sabes
  dónde vas a escribir ni con qué nombre, y podrías sobrescribir algo
  importante sin darte cuenta.
- **D podría tener valor en otros contextos** (ver si hay datos de
  aplicación sensibles), pero no es el paso prioritario para la vía de
  explotación de escritura de archivos.
- **B es correcto:** antes de modificar nada, hay que entender el estado
  actual — específicamente los parámetros `dir` (carpeta donde Redis
  persiste datos a disco) y `dbfilename` (nombre del archivo de volcado,
  por defecto `dump.rdb`).

</details>

---

## Decisión 3 — Conectando la pieza clave

Ya sabes que Redis permite `SET` (guardar cualquier valor arbitrario),
`CONFIG SET dir` (elegir carpeta de destino) y `CONFIG SET dbfilename`
(elegir nombre de archivo), más `SAVE` (forzar la escritura a disco).

### ¿Qué representa esta combinación de capacidades?

**A.** Una forma de hacer respaldos de la base de datos de forma remota, sin más implicaciones.
**B.** Una primitiva de escritura de archivos arbitraria en el sistema de archivos del servidor — el contenido, la ruta y el nombre del archivo quedan bajo control del atacante.
**C.** Solo es útil para modificar la configuración interna de Redis, no afecta nada fuera de la propia base de datos.
**D.** Requiere que el atacante ya tenga acceso SSH previo para ser útil.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A describe la función *legítima* del mecanismo**, pero ignora que
  nada impide apuntar `dir` fuera del directorio de datos normal de
  Redis — el mecanismo no distingue entre "guardar mi propio backup" y
  "escribir en cualquier carpeta del sistema a la que el proceso tenga
  acceso".
- **C subestima el alcance:** `dir` y `dbfilename` no están limitados al
  contexto interno de Redis — controlan una ruta real del sistema de
  archivos del sistema operativo completo.
- **D invierte el orden lógico:** esta técnica es precisamente la forma
  de **obtener** acceso SSH (vía `authorized_keys`), no un requisito
  previo para poder usarla.

</details>

---

## Decisión 4 — Eligiendo el objetivo de la escritura

Tienes dos objetivos candidatos para tu archivo malicioso: la carpeta
`.ssh` de un usuario (para inyectar una llave pública en
`authorized_keys`), o la carpeta raíz del servidor web (para dejar una
webshell).

### ¿Cuál priorizarías primero en este escenario, y por qué?

**A.** La webshell en el servidor web — siempre es más rápido obtener RCE vía HTTP.
**B.** La llave SSH — no depende de conocer la tecnología del backend web, algo que aún no confirmaste en este escenario.
**C.** Ambas al mismo tiempo, sin priorizar, para maximizar probabilidad de éxito.
**D.** Ninguna todavía — falta enumerar el puerto 80 a fondo antes de decidir.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A asume información que no tienes en este escenario:** no se
  confirmó si el backend del puerto 80 es PHP (o algún lenguaje
  interpretado en absoluto) — sin eso, una webshell podría no ejecutarse
  como código.
- **C es ineficiente y no reduce incertidumbre:** intentar ambas a la vez
  sin haber confirmado ningún requisito previo mezcla dos cadenas de
  explotación distintas sin necesidad.
- **D es válida en general**, pero en este caso puntual ya tienes una vía
  que **no depende** de esa información faltante (SSH) — postergar toda
  acción para enumerar más no es necesariamente la jugada de mayor
  retorno cuando ya existe un camino más autocontenido disponible.
- **B es la más eficiente:** generar tu propio par de llaves SSH es algo
  que controlas 100%, sin depender de ninguna suposición sobre el
  objetivo — reduce la incertidumbre de la cadena de ataque.

**Secuencia técnica de la explotación vía SSH:**
```bash
# 1. Generar el par de llaves en tu máquina atacante
ssh-keygen -t rsa -b 2048 -f /tmp/redis_key

# 2. Formatear la llave pública con saltos de línea de separación
(echo -e "\n\n"; cat /tmp/redis_key.pub; echo -e "\n\n") > /tmp/redis_key_formatted.txt

# 3. Conectarse a Redis y ejecutar la cadena de comandos
redis-cli -h <IP>
> config set dir /root/.ssh/
> config set dbfilename authorized_keys
> set x "<contenido de redis_key_formatted.txt>"
> save

# 4. Conectarse por SSH con la llave privada
ssh -i /tmp/redis_key root@<IP>
```

</details>

---

## Decisión 5 — La suposición que queda sin confirmar

Elegiste apuntar `dir` a `/root/.ssh/`, asumiendo la cuenta `root`.

### ¿Cuál es el riesgo real de esa elección? (más allá de "puede que root no exista")

**A.** Ninguno — el usuario `root` siempre existe en cualquier sistema Linux, así que la elección es segura.
**B.** El proceso de Redis podría no tener permisos de escritura en `/root/.ssh/` si no corre como root, y aunque la escritura funcione, Ubuntu suele deshabilitar el login SSH como root por defecto.
**C.** El único riesgo es que la llave pública tenga un formato incorrecto.
**D.** No hay ninguna forma de mitigar esta incertidumbre sin acceso previo al sistema.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A confunde dos cosas distintas:** que la cuenta `root` exista (cierto,
  siempre existe) no significa que **puedas escribir en su carpeta
  `.ssh`**, ni que **SSH vaya a aceptar una conexión como root** aunque
  la llave sea válida.
- **C es un riesgo menor y fácil de evitar** (formatear bien la llave),
  no el riesgo estructural real de la estrategia.
- **D es excesivamente pesimista:** sí existe mitigación — no depende de
  tener acceso previo, sino de tener un plan de contingencia con
  múltiples candidatos.

**Dos verificaciones que esta elección da por sentadas, sin confirmar:**
1. **¿Con qué privilegios corre el proceso de Redis?** Si no corre como
   root (buena práctica, pero no garantizada), no podrá escribir en
   `/root/.ssh/` — el `save` fallaría silenciosamente o con error de
   permisos.
2. **¿Permite Ubuntu login SSH como root?** Las instalaciones estándar de
   Ubuntu traen `PermitRootLogin` **deshabilitado por defecto** en
   `/etc/ssh/sshd_config` — la llave podría escribirse exitosamente y aun
   así SSH rechazar la conexión.

**Mitigación práctica:** intentar en paralelo/secuencia con varios
usuarios candidatos (`root`, más cualquier usuario identificado en otras
pistas de la enumeración), apuntando `dir` a `/home/<usuario>/.ssh/` en
cada intento adicional.

</details>

---

## Resumen de la cadena completa

```
Recon de puertos: no descartar servicios de datos (Redis) como "solo fuerza bruta"
        ↓
Conexión sin autenticación confirmada (ausencia total de auth, no fuerza bruta)
        ↓
Reconocimiento de configuración (INFO, CONFIG GET *) antes de modificar nada
        ↓
Identificación de la primitiva: SET + CONFIG SET dir/dbfilename + SAVE
        = escritura de archivo arbitraria en el sistema de archivos
        ↓
Elección del objetivo de menor incertidumbre (SSH, autocontenido)
        sobre el de mayor incertidumbre (webshell, depende del backend web)
        ↓
Escritura de clave pública en authorized_keys + conexión SSH
        ↓
Reconocimiento de que la suposición de usuario/privilegios sigue sin
confirmar del todo, con plan de mitigación (probar múltiples usuarios)
```

## Lección central del ejercicio

1. **No todo servicio de "acceso" tiene el mismo modelo de riesgo.** SSH y
   MySQL requieren credenciales por diseño; Redis, sin configuración
   adicional, no — agruparlos bajo "fuerza bruta" es una simplificación
   que puede hacerte pasar por alto el vector más directo.
2. **Cuando dos vías de explotación son posibles, prioriza la que dependa
   de menos suposiciones no confirmadas** sobre el objetivo — generar tu
   propia llave SSH es información 100% bajo tu control; asumir un
   lenguaje de backend web sin haberlo confirmado no lo es.
3. **Incluso la vía "más segura" (SSH) tiene sus propias suposiciones
   implícitas** (privilegios del proceso, configuración de `sshd`) que
   vale la pena nombrar explícitamente y tener un plan B, en vez de
   asumir que un solo intento va a funcionar.
