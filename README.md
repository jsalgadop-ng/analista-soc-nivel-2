# SOC L2 Analyzer

Aplicación web en Python (Streamlit) para investigar un posible incidente de seguridad a partir de los logs
exportados del SIEM de un cliente (Excel `.xlsx`).

A partir del archivo, la aplicación:

1. **Detecta** eventos sospechosos con un motor de reglas explicables.
2. **Correlaciona** los hallazgos en incidentes y reconstruye la cadena de ataque.
3. **Clasifica el riesgo** (Crítico / Alto / Medio / Bajo, puntaje 0-100) con los factores que lo justifican.
4. Muestra un **dashboard interactivo** filtrable.
5. Genera dos informes descargables en **PDF** y **Markdown**: un *informe técnico* completo y un *informe ejecutivo* de
   2 páginas para la alta dirección.
6. Ofrece un **asistente de IA (Claude)** para consultar los logs en lenguaje natural y redactar los informes.

Reto final del Bootcamp *Analista SOC Nivel 2*.

> **Principio rector: no se inventa nada.** Todo hallazgo se apoya en Log_IDs que existen en el archivo cargado, y toda
> cita o cifra que produce la IA se verifica automáticamente antes de que llegue a un informe.

---

## Índice

1. [Puesta en marcha](#1-puesta-en-marcha)
2. [Configuración](#2-configuración)
3. [Guía de uso, pestaña por pestaña](#3-guía-de-uso-pestaña-por-pestaña)
4. [Formato del archivo de entrada](#4-formato-del-archivo-de-entrada)
5. [Cómo funciona el análisis](#5-cómo-funciona-el-análisis)
6. [Qué detecta](#6-qué-detecta)
7. [Clasificación de riesgo](#7-clasificación-de-riesgo)
8. [Integración con IA](#8-integración-con-ia)
9. [Informes](#9-informes)
10. [Resultado con el archivo del reto](#10-resultado-con-el-archivo-del-reto)
11. [Rigor, límites y privacidad](#11-rigor-límites-y-privacidad)
12. [Arquitectura y estructura del proyecto](#12-arquitectura-y-estructura-del-proyecto)
13. [Pruebas](#13-pruebas)
14. [Cómo extender la aplicación](#14-cómo-extender-la-aplicación)
15. [Solución de problemas](#15-solución-de-problemas)

---

## 1. Puesta en marcha

**Requisitos:** Python 3.11 o superior (desarrollado y probado con 3.13).

| Dependencia | Versión mínima | Uso |
|-------------|----------------|-----|
| streamlit | 1.66 | Interfaz web |
| pandas | 3.0 | Carga y análisis de logs |
| openpyxl | 3.1 | Lectura del `.xlsx` |
| plotly | 7.1 | Gráficos interactivos del dashboard |
| matplotlib | 3.11 | Gráficos incrustados en el PDF |
| fpdf2 | 2.8.8 | Generación de los PDF |
| anthropic | 2.3 | Cliente de la API de Claude |
| pytest | 9.0 | Pruebas |

```bash
pip install -r requirements.txt
streamlit run app.py
```

En Windows basta con hacer doble clic en [iniciar.bat](iniciar.bat): instala las dependencias (solo la primera vez) y
abre la aplicación. Por defecto queda en `http://localhost:8501`. Para otro puerto:
`streamlit run app.py --server.port 8601`.

**Enlaces de demostración** (parámetros de la URL):

| URL | Efecto |
|-----|--------|
| `?demo=1` | Carga directamente el archivo del reto (`Insumos/SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`). La carpeta `Insumos/` no se incluye en el repositorio: al clonarlo, créela y copie ahí el archivo, o cargue el Excel manualmente. |
| `?p=N` | Abre la pestaña N (1-6). |
| `?demo=1&p=3` | Carga el archivo del reto y abre el dashboard. |

---

## 2. Configuración

### API key de Anthropic (opcional)

La IA es opcional. **Sin clave, el análisis por reglas, el dashboard y ambos informes en PDF funcionan igualmente**; solo
se desactivan el chat y la redacción con IA. La clave se busca en este orden:

1. Campo *API key de Anthropic* de la barra lateral (*🤖 Configuración de IA*). Es un campo de contraseña y solo vive
   en la sesión del navegador.
2. `.streamlit/secrets.toml`:
   ```toml
   ANTHROPIC_API_KEY = "sk-ant-..."
   ```
3. Variable de entorno `ANTHROPIC_API_KEY`.

> `.streamlit/secrets.toml` está excluido del control de versiones por [.gitignore](.gitignore). No lo comparta ni lo
> suba a un repositorio, y revoque la clave cuando deje de necesitarla.

### Modelo de IA

Se elige en la misma sección de la barra lateral:

| Modelo | Perfil |
|--------|--------|
| `claude-opus-5-5` (por defecto) | Máxima calidad |
| `claude-sonnet-5-5` | Rápido |
| `claude-haiku-5-5` | Económico |

### Tema visual

Tema sepia claro definido en [.streamlit/config.toml](.streamlit/config.toml) (fondo `#f4ecd8`, acento `#9a5418`). Los
colores de criticidad (`soc_analyzer/risk.py`) y la paleta de los gráficos están validados contra ese fondo para
distinguirse también con daltonismo, y el color nunca es la única señal: siempre va acompañado de la etiqueta del nivel.

### Parámetros de detección

Se ajustan en la barra lateral (*⚙️ Parámetros de detección*); al cambiarlos, el análisis se recalcula al instante:

| Parámetro | Valor por defecto | Significado |
|-----------|-------------------|-------------|
| Fallos para fuerza bruta (origen interno) | 10 | Fallos 4625 en una ráfaga desde una IP interna |
| Fallos para fuerza bruta (origen Internet) | 3 | Umbral reducido si el origen es externo |
| Cuentas distintas para *password spraying* | 5 | Cuentas atacadas por un mismo origen |
| Archivos para acceso masivo | 10 | Archivos accedidos en una ventana corta |
| MB salientes para exfiltración | 50 | Volumen de subida por proxy |
| Ventana de correlación (min) | 90 | Distancia máxima entre hallazgos del mismo incidente |
| Inicio / fin del horario laboral | 7 / 20 | Para marcar actividad fuera de horario |

Otros parámetros internos de [DetectionConfig](soc_analyzer/detections.py): separación máxima entre intentos de una
ráfaga (10 min), ventana de "éxito tras ataque" (60 min) y repeticiones mínimas para considerar ejecución periódica (3).

---

## 3. Guía de uso, pestañas por pestaña

La navegación es una fila de pestañas en la parte superior. Solo se ejecuta la pestaña abierta, así que la aplicación
responde con rapidez aunque el análisis sea grande.

### Barra lateral

Muestra el archivo cargado, el número de eventos e incidentes con una insignia por nivel, la configuración de IA (con
indicador 🟢 configurada / ⚪ solo reglas) y los parámetros de detección.

### 📂 1. Carga de datos

- Arrastre el `.xlsx` o pulse **Usar archivo del reto**.
- Se calcula el **SHA-256** del archivo (cadena de custodia) y se muestra la hoja usada.
- Se muestran métricas del conjunto (registros, equipos, cuentas, IPs de origen, duración) y los **avisos de carga**
  (columnas ausentes, fechas inválidas descartadas, Log_ID duplicados).
- Tabla de registros con búsqueda libre sobre todos los campos y filtros por equipo y Event ID.

### 🔍 2. Análisis de seguridad

- **Cobertura de detección:** tarjetas con las categorías que evalúa el motor.
- **Incidentes correlacionados:** un panel por incidente con nivel, puntaje, justificación, entidades implicadas
  (cuentas y equipos), una pestaña por hallazgo (descripción, explicación técnica, técnicas MITRE ATT&CK, factores de
  riesgo y la **tabla de evidencia con los Log_ID**) y una pestaña de **impacto y plan de acción** (investigar /
  contener / remediar).
- **Observaciones de bajo riesgo:** lo que se evaluó y se descartó como ruido, documentado en lugar de ocultarse.

### 📊 3. Dashboard

Filtros por **criticidad**, **categoría** y **periodo**; todo lo de la página se recalcula con ellos.

- Seis indicadores: eventos en el periodo, incidentes, críticos, hallazgos, IPs externas y cuentas comprometidas.
- Línea de tiempo de incidentes, incidentes y hallazgos por criticidad, mapa de la cadena de ataque (táctica por hora),
  volumen de eventos con los implicados en hallazgos, principales IPs de origen, tipos de evento más frecuentes, mapa de
  calor de actividad sospechosa por equipo y hora, y hallazgos por táctica.
- Una tabla alternativa ("Ver datos en tabla") para quien prefiera los datos a los gráficos.

### ⚖️ 4. Clasificación de riesgos

Metodología (rangos y significado de cada nivel), gráfico de puntaje por hallazgo, clasificación de incidentes con su
desglose de factores y tabla de detalle por hallazgo.

### 🤖 5. Asistente IA

Chat en lenguaje natural sobre los logs y los hallazgos. Hay preguntas sugeridas. Cada respuesta se muestra en
streaming con una **barra de progreso** (fase de preparación y de redacción) y, al terminar, un aviso verde o amarillo
indica si todos los Log_ID citados existen en el archivo. Las citas inexistentes se marcan con
`⚠️(no existe en los logs)`. Requiere API key.

### 📄 6. Informe técnico

Selector **Tipo de informe**:

- **📘 Informe técnico:** análisis completo con evidencias (unas 25 páginas con el archivo del reto).
- **📋 Informe ejecutivo:** resumen de 2 páginas en lenguaje no técnico para la alta dirección.

Ambos comparten el formulario de datos del informe (analista, cliente, ID de caso, organización), el botón de redacción
con IA, la exportación a PDF y a Markdown y una vista previa. Detalle en la [sección 9](#9-informes).

---

## 4. Formato del archivo de entrada

Un `.xlsx` con una hoja de eventos. Si hay varias hojas se elige la que tiene más columnas reconocibles. Columnas
canónicas:

| Columna | Obligatoria | Ejemplo / uso |
|---------|:-----------:|----------------|
| `Timestamp` | ✅ | Fecha y hora del evento |
| `Event_ID` | ✅ | `4624`, `4625`, `4688`, `4698`, `7045`… además de `HTTP_ACCESS` y `PROXY_ACCESS` |
| `Log_ID` | — | Identificador de la evidencia (`EVT-00123`). Si falta se generan `ROW-00001`… |
| `Hostname` | — | Equipo que registra el evento |
| `User` | — | `CORP\mgarcia` |
| `Source_IP` | — | Origen del evento |
| `Destination` | — | Destino (IP, recurso, URL) |
| `Log_Source` | — | `Security`, `Sysmon`, `IIS`, `Proxy`… |
| `Event_Description` | — | Texto del evento (`LogonType = 3`, `file share access: …`) |
| `Process_CommandLine` | — | Línea de comandos, URI o `bytes_out=…` |
| `Result` / `Severity` | — | Resultado y severidad de la fuente |

Se aceptan **nombres equivalentes** de columna, sin distinguir mayúsculas, espacios ni guiones bajos (por ejemplo
`Fecha`, `Equipo`, `Usuario`, `IP Origen`, `Descripcion`, `CommandLine`). Una columna ausente se asume vacía y se avisa.

Reglas de limpieza: las filas con fecha no interpretable se descartan (y se avisa), `Event_ID` guardado como `4625.0` se
normaliza, las cadenas vacías pasan a nulos y los registros se ordenan por fecha. Si faltan `Timestamp` o `Event_ID`, o no
queda ningún registro válido, se muestra un error claro.

---

## 5. Cómo funciona el análisis

```
Excel (.xlsx)
   │  loader.py      normaliza columnas, tipos y SHA-256
   ▼
Logs limpios
   │  features.py    columnas derivadas: IP externa, LogonType, bytes, URI, ruta de archivo…
   ▼
Logs enriquecidos
   │  detections.py  10 detectores de reglas  →  Hallazgos (H-01…) con Log_ID, MITRE y factores de riesgo
   ▼
Hallazgos
   │  correlation.py agrupa por cuenta/IP del actor en una ventana temporal  →  Incidentes (INC-01…)
   ▼
Incidentes ordenados por criticidad + estadísticas
   │            ┌───────────────┬──────────────────┬────────────────────┐
   ▼            ▼               ▼                  ▼                    ▼
 Interfaz   Dashboard     Asistente IA        Informe técnico     Informe ejecutivo
```

La orquestación está en [pipeline.py](soc_analyzer/pipeline.py) (`run_analysis`).

### Detectores y orden de ejecución

Cada detector recibe el conjunto de eventos ya "consumidos" por los anteriores, de modo que un mismo evento no genera
hallazgos duplicados. Los tres últimos (movimiento lateral, exfiltración, anomalías y ruido) además consultan los
hallazgos previos para dar contexto.

1. Ataques de credenciales  2. Inicios de sesión sospechosos  3. Escalamiento de privilegios  4. Persistencia
5. Ataques web  6. Comandos y procesos  7. Movimiento lateral  8. Exfiltración  9. Entidades anómalas  10. Ruido de
autenticación.

### Correlación en incidentes

Dos hallazgos pertenecen al mismo incidente si **comparten una entidad pivote** (la cuenta o la IP del actor) y ocurren
a menos de la ventana de correlación (90 min por defecto). Se usa una unión de conjuntos (*union-find*).

- Compartir **solo un equipo** o **solo una cuenta objetivo** no basta para fusionar. Esos vínculos se informan como
  *"relación posible, no confirmada por los logs"* para no afirmar más de lo que prueban los datos.
- Los hallazgos de nivel Bajo sin entidad pivote (ruido evaluado y descartado) pasan a **observaciones**, no a incidentes.
- Cada incidente recibe un título descriptivo (por ejemplo *Actividad precursora de ransomware*), la lista de tácticas
  MITRE ATT&CK implicadas, su impacto potencial (con los activos reales del caso) y un **plan de acción** en tres fases:
  *investigar*, *contener* y *remediar*, tomado de los *playbooks* de [knowledge.py](soc_analyzer/knowledge.py) y rellenado
  con las cuentas, equipos e IPs del incidente.

---

## 6. Qué detecta

| Categoría | Detección |
|-----------|-----------|
| Fuerza bruta | Ráfagas de 4625 por origen; distingue *password spraying* (muchas cuentas) de fuerza bruta (una cuenta); umbral reducido si el origen es Internet. |
| Inicios sospechosos | Éxito tras un ataque de credenciales desde el mismo origen, logons desde IP externa, RDP, fuera de horario. |
| Escalamiento | Privilegios especiales (4672) en sesiones de origen externo; altas en grupos privilegiados (4728/4732/4756) y creación de cuentas (4720). |
| Comandos y procesos | PowerShell codificado/ofuscado, borrado de copias de sombra, volcado de credenciales, LOLBins, reconocimiento, ejecución desde rutas inusuales. |
| Persistencia | Tareas programadas (4698), servicios (7045), claves Run, nombres que imitan a Windows y ejecución periódica de binarios. |
| Movimiento lateral | Logons de red (LogonType 3/10) de cuentas ya comprometidas hacia otros equipos, precedidos de enumeración (`net view`) y seguidos de acceso a recursos compartidos. |
| Recolección y exfiltración | Compresión de datos (*staging*), subidas voluminosas por proxy, conexiones salientes de intérpretes a Internet y acceso masivo a archivos. |
| Ataques web | Webshells, SQLi, path traversal, acceso a paneles y exportaciones, y ejecución de procesos por la cuenta del servidor web. |
| Otras anomalías | Cuentas o equipos con nombres que imitan a otros legítimos (`DC01` frente a `DC-01`) y entidades con presencia acotada en la captura. |

### Reglas de comandos y técnicas MITRE ATT&CK

Las reglas de línea de comandos son datos (`COMMAND_RULES` en [detections.py](soc_analyzer/detections.py)), cada una con su
expresión regular, técnicas ATT&CK, categoría, peso base y una explicación en lenguaje claro:

| Regla | Técnicas | Peso base |
|-------|----------|:---------:|
| Eliminación de copias de sombra | T1490 | 65 |
| Volcado de credenciales | T1003 | 65 |
| Desactivación de defensas / borrado de logs | T1562.001, T1070.001 | 55 |
| PowerShell con comando codificado en Base64 | T1059.001, T1027 | 40 |
| Descarga de herramientas con binarios del sistema (LOLBins) | T1105 | 40 |
| PowerShell con evasión o descarga en memoria | T1059.001, T1140 | 35 |
| Compresión de datos para extracción (*staging*) | T1560.001, T1074.001 | 35 |
| Ejecución de binario desde ruta inusual | T1036, T1204.002 | 30 |
| Enumeración de grupos privilegiados | T1069 | 25 |
| Descubrimiento de recursos compartidos | T1135 | 25 |
| Reconocimiento del sistema y del usuario | T1033, T1082 | 20 |

### Detalles de rigor en las detecciones

- **IP externa:** solo RFC 1918, *loopback* y *link-local* se consideran internas. Las redes de documentación
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), que Python marca como "privadas" pero que en exports de laboratorio
  representan Internet, se tratan como **externas**.
- **Nombres que imitan a otros** (*lookalikes*): se compara el nombre normalizado de cuentas y equipos para encontrar
  parejas como `DC01`/`DC-01` o `svc_backup`/`backupsvc`.
- **Ejecución periódica:** se mide la cadencia (intervalo medio y coeficiente de variación) para distinguir una tarea
  automática de actividad humana.

---

## 7. Clasificación de riesgo

La metodología es deliberadamente simple y verificable ([risk.py](soc_analyzer/risk.py)):

**Puntaje de un hallazgo** = puntaje base de la técnica observada + factores agravantes explícitos (éxito del ataque,
activo crítico, origen externo, salida de datos…), limitado a 0-100. Cada factor se muestra con sus puntos y su razón.

**Puntaje de un incidente** = puntaje del hallazgo más grave + bonificaciones de cadena:

| Concepto | Puntos |
|----------|:------:|
| Cadena multi-etapa (varias tácticas ATT&CK) | +4 por táctica adicional, máx. +12 |
| Patrón completo de exfiltración (compresión + envío al exterior) | +10 |
| Patrón precursor de ransomware (acceso masivo + borrado de copias de sombra) | +10 |

**Niveles:**

| Nivel | Puntaje | Significado | Respuesta |
|-------|:-------:|-------------|-----------|
| 🟥 Crítico | ≥ 80 | Compromiso confirmado o pérdida/destrucción de datos en curso | Inmediata |
| 🟧 Alto | 60-79 | Actividad maliciosa con alta probabilidad de éxito o sobre activos críticos | En horas |
| 🟨 Medio | 35-59 | Actividad sospechosa que requiere validación y seguimiento | En el día |
| 🟦 Bajo | < 35 | Comportamiento atípico de bajo impacto o ruido operativo | Monitorear |

La criticidad es una **estimación basada en reglas documentadas, no un dictamen forense**; los informes lo indican.

---

## 8. Integración con IA

Implementada en [ai_assistant.py](soc_analyzer/ai_assistant.py) con el SDK oficial de Anthropic.

### Qué hace la IA

| Función | Qué recibe | Qué produce |
|---------|------------|-------------|
| **Chat** (pestaña 5) | Logs + hallazgos + incidentes | Respuestas con Log_ID citados, en streaming |
| **Redacción del informe técnico** | Logs + hallazgos + incidentes | JSON estructurado (esquema validado): resumen ejecutivo, análisis e impacto por incidente, recomendaciones, limitaciones |
| **Resumen del informe ejecutivo** | **Solo** los hechos ya verificados (sin logs ni IPs) | Uno o dos párrafos de máximo 130 palabras |

### Reglas que se le imponen

- Usar **exclusivamente** los registros y hallazgos incluidos; no inventar eventos, IPs, usuarios, archivos, volúmenes ni
  horarios.
- Citar Log_ID entre corchetes en cada afirmación factual, sin rangos.
- Distinguir **hecho** (visible en los logs), **inferencia** y **hipótesis**, y declarar "no hay evidencia en los
  registros" cuando corresponda.
- No cambiar los niveles de criticidad calculados por el motor; si cree que alguno debe revisarse, indicarlo como
  observación justificada.
- Para el resumen ejecutivo: sin jerga, sin IPs ni identificadores de log, y reflejando el grado de certeza (decir *"hay
  indicios de…"* en lugar de *"el atacante controló…"* cuando solo hay indicios).
- El uso es defensivo: explicar, priorizar y recomendar medidas, no generar herramientas ofensivas.

### Verificación automática

| Verificación | Cómo funciona | Si falla |
|--------------|---------------|----------|
| **Citas de Log_ID** | Cada token entre corchetes se comprueba contra los Log_ID, hallazgos e incidentes reales. | Se marca `⚠️(no existe en los logs)` en la app y en el PDF; el aviso pasa a amarillo. |
| **Cifras del resumen ejecutivo** | Cada número del texto de la IA debe aparecer en los hechos que se le entregaron. | La app avisa con las cifras no respaldadas antes de distribuir el informe. |

### Detalles técnicos

- **Contexto:** hasta 2 500 registros se envían completos (CSV); si el archivo es mayor, solo los asociados a hallazgos,
  y la IA recibe una nota para que declare esa limitación.
- **Caché de prompt:** el bloque de logs lleva `cache_control`, de modo que las preguntas sucesivas del chat reutilizan el
  contexto y salen más baratas.
- **Esfuerzo de razonamiento:** `medium` en chat y resumen ejecutivo, `high` en la redacción del informe técnico.
- **Respaldo de modelo:** con Opus y Sonnet se activa el reintento en otro modelo del lado del servidor (*fallback*)
  si un clasificador declina la petición; por eso el modelo que responde puede diferir del elegido y la app indica
  cuál fue ("redactado por `claude-opus-5-5`").
- **Barra de progreso:** las llamadas se ejecutan en un hilo; la barra avanza en dos fases (preparación y redacción) según
  los caracteres recibidos, con el tiempo transcurrido.
- **Errores:** se traducen a mensajes claros (clave inválida, sin permisos, modelo no disponible, límite de uso, sin
  conexión) y los rechazos del modelo se explican al usuario.

---

## 9. Informes

Ambos informes comparten los datos del caso (analista, cliente, ID de caso, organización) y se pueden generar con o sin IA.

### 📘 Informe técnico (PDF de unas 25 páginas y Markdown)

Portada con el nivel de riesgo y las cifras clave, índice navegable y estas secciones:

1. **Resumen ejecutivo**
2. **Alcance y metodología** (archivo, SHA-256, periodo, fuentes, método de clasificación)
3. **Hallazgos identificados** (tabla con nivel y puntaje)
4. **Análisis detallado de incidentes:** descripción, cronología, evidencia (tabla de Log_ID, hasta 30 filas por
   incidente), explicación técnica, impacto y plan de acción
5. **Línea de tiempo consolidada**
6. **Indicadores de compromiso (IoC)**
7. **Observaciones evaluadas de bajo riesgo** (si las hay)
8. **Recomendaciones generales de seguridad**
9. **Limitaciones del análisis**

Incluye gráficos (niveles, línea de tiempo, volumen de eventos). Con IA se añaden resumen ejecutivo redactado, narrativa
por incidente y recomendaciones, y el PDF refleja la verificación de citas.

### 📋 Informe ejecutivo (PDF de 2 páginas y Markdown)

Pensado para quien no maneja temas técnicos. **Sin IPs, Log_IDs ni códigos de evento** (eso queda en el técnico).

| Bloque | Contenido |
|--------|-----------|
| Nivel global de riesgo | El mayor nivel entre los incidentes, con su significado |
| Cuatro cifras | Incidentes, críticos, equipos implicados, direcciones de Internet implicadas |
| Resumen y *Lo más importante* | Un párrafo y cinco viñetas |
| Qué ocurrió | Un bloque por incidente: nivel, titular (por ejemplo *Preparativos de un ataque de ransomware*), hechos clave, qué está en riesgo y sistemas intervinientes |
| Decisiones y acciones inmediatas (hoy) | Solo las que aplican a lo detectado |
| Próximos pasos (esta semana) | Plan a corto plazo |
| Qué falta por confirmar | Alcance temporal, comandos ocultos, volúmenes no registrados, relaciones no demostradas |

**Cómo se mantiene fiel a los logs** ([executive.py](soc_analyzer/executive.py)):

- Cada frase se genera a partir de un **tipo de hallazgo** (por categoría e ID MITRE), no de texto libre.
- Las acciones son condicionales: verificar las copias de seguridad solo si hubo borrado de copias; consulta legal por el
  RGPD solo si hubo salida de datos.
- El resumen con IA (botón *✨ Redactar resumen con IA*) parte únicamente de esos hechos y se somete a la verificación de
  cifras. Se puede descartar para volver al texto determinista.
- Con el archivo del reto ocupa **exactamente 2 páginas**, con o sin IA; con muchos más incidentes ocuparía más.
- Incluye la advertencia de que el aislamiento de equipos puede causar interrupciones breves de servicio, y que la
  criticidad es una estimación.

---

## 10. Resultado con el archivo del reto

`SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx` (hoja *SIEM Export*): **715 eventos** del 23/10/2026 entre las 07:46 y
las 13:44, **11 equipos, 13 cuentas, 10 IPs de origen**. El motor produce **18 hallazgos**, **1 observación** de bajo riesgo
y **7 incidentes** (5 críticos, 2 altos):

| Incidente | Nivel | Puntaje | Qué es |
|-----------|:-----:|:-------:|--------|
| INC-03 | Crítico | 100 | Intrusión con movimiento lateral y exfiltración de datos |
| INC-05 | Crítico | 100 | Exfiltración de datos hacia un destino externo desde una cuenta interna |
| INC-07 | Crítico | 95 | Explotación de aplicación web (webshell) |
| INC-04 | Crítico | 94 | Actividad precursora de ransomware (borrado de copias de sombra tras acceso masivo) |
| INC-01 | Crítico | 93 | Compromiso de cuenta por password spraying seguido de inicio de sesión exitoso |
| INC-06 | Alto | 70 | Implantación de mecanismos de persistencia |
| INC-02 | Alto | 60 | Entidades anómalas y posible suplantación de nombres (`DC01`) |

Los incidentes se numeran por orden de aparición temporal y se listan por criticidad. El detalle completo, con
evidencias, se ve en la pestaña *Análisis de seguridad* o en el informe técnico.

---

## 11. Rigor, límites y privacidad

### Garantías de rigor

- Ningún hallazgo existe sin los Log_ID que lo respaldan; la prueba `test_toda_evidencia_existe_en_el_archivo` lo
  comprueba sobre el archivo del reto.
- La clasificación es transparente: puntaje base por técnica más factores agravantes explícitos.
- Las relaciones entre incidentes que los logs no demuestran se declaran como *posibles, no confirmadas*.
- Lo evaluado y descartado se documenta como observación en lugar de silenciarse.
- La IA nunca altera los niveles de criticidad, y toda cita o cifra suya se verifica contra los datos.

### Límites conocidos

- El análisis se limita a los registros exportados: actividad anterior o posterior y otras fuentes no cubiertas quedan fuera.
- Los comandos ofuscados o redactados en el export no pueden analizarse; se listan en las limitaciones.
- No hay telemetría de EDR, DNS ni captura de red, por lo que los volúmenes solo se conocen si el log los registra.
- Las detecciones son reglas heurísticas con umbrales ajustables: no sustituyen la revisión de un analista, y un umbral
  mal ajustado puede producir falsos positivos o negativos.
- Los informes y planes de acción son una base para la respuesta, no una confirmación forense.

### Privacidad

- El análisis por reglas y los PDF se generan **localmente**; nada sale de su equipo.
- Si usa la IA, el **chat y la redacción del informe técnico envían los registros** (hasta 2 500 completos, o los asociados
  a hallazgos si hay más) y los hallazgos a la API de Anthropic. El **resumen ejecutivo envía solo los hechos
  resumidos**, sin logs ni IPs. Revise la política de tratamiento de datos de su cliente antes de usar la IA con logs reales.
- La API key introducida en la barra lateral no se guarda en disco.
- El archivo cargado se identifica con su SHA-256 para la cadena de custodia.

---

## 12. Arquitectura y estructura del proyecto

```
Analista SOC nivel 2/
├── app.py                      Interfaz Streamlit: 6 pestañas, barra lateral, progreso de la IA y estilos sepia
├── iniciar.bat                 Instala dependencias y abre la app (Windows)
├── requirements.txt            Dependencias
├── pytest.ini                  Configuración de las pruebas
├── .streamlit/
│   ├── config.toml             Tema sepia y límite de subida (50 MB)
│   └── secrets.toml            API key (no versionar)
├── Insumos/                    Archivo de logs del reto y lineamientos (excluida del repositorio por .gitignore)
├── soc_analyzer/
│   ├── loader.py               Lectura y normalización del Excel, alias de columnas y SHA-256
│   ├── features.py             Columnas derivadas (IP externa, LogonType, bytes, rutas…), ráfagas y cadencia
│   ├── detections.py           Motor de reglas: 10 detectores, DetectionConfig y COMMAND_RULES
│   ├── models.py               Dataclasses Finding, RiskFactor e Incident
│   ├── correlation.py          Agrupación en incidentes, impacto, plan de acción y relaciones posibles
│   ├── risk.py                 Niveles, umbrales, colores y bonificaciones de cadena
│   ├── knowledge.py            Categorías, tácticas ATT&CK, impacto, playbooks y recomendaciones generales
│   ├── pipeline.py             run_analysis(): orquesta todo y calcula estadísticas
│   ├── ai_assistant.py         Cliente de Claude, prompts, esquema JSON y verificación de citas
│   ├── charts.py               Gráficos interactivos (Plotly) del dashboard
│   ├── report.py               Informe técnico (Markdown y PDF) y utilidades de PDF compartidas
│   └── executive.py            Informe ejecutivo (lenguaje llano, Markdown y PDF de 2 páginas)
└── tests/
    ├── test_analysis.py        11 pruebas del motor de análisis
    └── test_executive.py       9 pruebas del informe ejecutivo
```

### Decisiones de diseño

- **Reglas explicables antes que IA.** Las detecciones y la clasificación son deterministas y auditables; la IA se limita a
  explicar, redactar y responder, con verificación.
- **Resultado inmutable respecto de la interfaz.** `run_analysis` devuelve un `AnalysisResult` que todas las pestañas leen;
  la interfaz no recalcula lógica de negocio.
- **Hallazgos con identidad estable** (`H-01`, `INC-01`) para poder citarlos en la IA, en el PDF y en las pruebas.
- **Contenido compartido entre vista previa y PDF.** Markdown y PDF se construyen desde los mismos datos para que no
  diverjan.
- **Fuentes DejaVu** en los PDF para soportar tildes y símbolos en español.

---

## 13. Pruebas

```bash
python -m pytest
```

20 pruebas, todas pasan (≈ 7 s). Cubren, entre otras cosas:

| Archivo | Qué verifica |
|---------|--------------|
| `test_analysis.py` | Los 7 incidentes esperados del archivo del reto; *password spraying* y cuenta comprometida; intrusión RDP con movimiento lateral y exfiltración; ransomware, persistencia, webshell y anomalías; que el ruido no sea incidente; que **toda evidencia exista en el archivo**; verificación de citas; PDF y Markdown; redes de documentación tratadas como externas; datos benignos sin incidentes; columnas obligatorias. |
| `test_executive.py` | Un bloque por incidente con su nivel; ausencia de IPs, Log_IDs y códigos técnicos en el texto; hechos clave sustentados (por ejemplo 241.6 MB exfiltrados); declaración de lo no confirmado; PDF ejecutivo de **2 páginas**; detección de cifras inventadas por la IA; que sin incidentes el informe siga generándose. |

Si el archivo del reto no está en `Insumos/`, las pruebas que dependen de él se omiten.

---

## 14. Cómo extender la aplicación

**Añadir una regla de línea de comandos.** Agregue una entrada a `COMMAND_RULES` en
[detections.py](soc_analyzer/detections.py) con su expresión regular, nombre, técnicas ATT&CK, categoría, peso base y
explicación. No hace falta tocar nada más: el motor, la correlación, el dashboard y los informes la recogen.

**Añadir un detector nuevo.** Escriba una función `detect_xxx(d, cfg, consumed)` que devuelva una lista de `Finding`
(con `evidence_ids`, `pivots`, `mitre` y factores de riesgo) y regístrela en `run_detectors`. Los pivotes son lo que
permite que el hallazgo se correlacione con otros (`user:CORP\\ana`, `ip:203.0.113.5`).

**Añadir una categoría.** Defínala en `CATEGORIES` (etiqueta, táctica, icono) de [knowledge.py](soc_analyzer/knowledge.py)
en su posición dentro de la cadena de ataque, y agregue su impacto y su *playbook* de investigar / contener / remediar.

**Cambiar niveles o colores.** Edite `THRESHOLDS`, `LEVEL_COLORS` y `LEVEL_DESCRIPTIONS` en
[risk.py](soc_analyzer/risk.py). Si cambia colores, valide la paleta contra el fondo y recuerde que el color debe ir
siempre acompañado de la etiqueta.

> Streamlit cachea los módulos importados. Tras cambiar código de `soc_analyzer/`, **reinicie el servidor**
> (`Ctrl+C` y `streamlit run app.py`) para ver el cambio.

---

## 15. Solución de problemas

| Síntoma | Causa probable y solución |
|---------|---------------------------|
| "No se pudo abrir el archivo como Excel" | El archivo no es un `.xlsx` válido o está dañado. Guárdelo de nuevo desde Excel como `.xlsx`. |
| "Faltan columnas obligatorias" | El archivo no tiene `Timestamp` o `Event_ID` (ni un alias reconocido). Renombre las columnas. |
| Aviso "registros con fecha no interpretable" | Hay filas con fecha inválida; se descartan. Revise el formato de fecha de origen. |
| Aviso "Hay Log_ID duplicados" | Las referencias de evidencia pueden ser ambiguas; corrija el identificador en el SIEM. |
| El botón de IA está desactivado / "IA: ⚪ no configurada" | Configure la API key (barra lateral, `secrets.toml` o variable de entorno). |
| "La API key de Anthropic no es válida" | La clave es incorrecta o fue revocada. |
| "Límite de uso de la API alcanzado" | Espere un momento y reintente; considere un modelo más económico. |
| "No hay conexión con la API de Anthropic" | Revise la red o el proxy corporativo. |
| "La respuesta del modelo se truncó" | Vuelva a intentarlo; en archivos muy grandes, reduzca el periodo. |
| Aviso amarillo "referencias verificadas… No existen en el archivo" | La IA citó un Log_ID inexistente. La cita queda marcada; no la use sin comprobar. |
| Aviso "contiene cifras que no figuran en los hechos" | El resumen ejecutivo con IA incluye un número no respaldado. Revíselo, descártelo o vuelva a generarlo. |
| El PDF ejecutivo ocupa más de 2 páginas | Hay muchos más incidentes que en el archivo del reto; es el comportamiento esperado. |
| Cambié el código y la app no lo refleja | Reinicie el servidor de Streamlit (ver sección 14). |
| No aparecen incidentes con mis datos | Los datos pueden ser benignos, o los umbrales demasiado altos: ajuste *Parámetros de detección* en la barra lateral. |
