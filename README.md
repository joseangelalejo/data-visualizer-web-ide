# 🌟 JSON/CSV Data Visualizer & Web IDE

Aplicación web moderna para explorar archivos **JSON/CSV** y conectarse a múltiples bases de datos. Tablas interactivas, gráficos dinámicos, diagramas ER automáticos e IDE SQL integrado con Monaco Editor.

🌐 **[json-csv-visualizerv1.vercel.app](https://json-csv-visualizerv1.vercel.app)**

<div align="center">

![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=next.js&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)

</div>

## ✨ Características principales

✅ **Carga de archivos** — JSON y CSV explorados instantáneamente  
✅ **Múltiples BDD** — SQLite, PostgreSQL, MySQL, MongoDB  
✅ **Tablas interactivas** — Paginación, ordenación, búsqueda, filtros  
✅ **Gráficos dinámicos** — Barras, líneas, pastel, histogramas  
✅ **Diagramas ER** — Visualización automática de relaciones  
✅ **IDE SQL** — Editor Monaco con autocompletado y ejecución  
✅ **Exporta a CSV** — Descarga resultados en un clic  
✅ **Interfaz moderna** — Gradientes vibrantes, responsive, animaciones  

## 🛠️ Stack técnico

| Capa           | Tecnología                                 |
|----------------|--------------------------------------------|
| **Frontend**   | Next.js 16 + React 19 + TypeScript         |
| **Estilos**    | Tailwind CSS + componentes personalizados  |
| **Editor SQL** | Monaco Editor                              |
| **Gráficos**   | Chart.js / Recharts                        |
| **BD**         | Soporte SQLite, PostgreSQL, MySQL, MongoDB |
| **Deploy**     | Vercel + Docker                            |
| **Auth**       | JWT opcional                               |

## 🗄️ Bases de datos soportadas

- ✅ **SQLite** — Local, sin servidor
- ✅ **PostgreSQL** — Conecciones remotas
- ✅ **MySQL** — Compatible con TiDB Cloud
- ✅ **MongoDB** — Documentos NoSQL

## 🚀 Quick Start

```bash
# Clonar repositorio
git clone https://github.com/joseangelalejo/json-csv-visualizerv1.git
cd json-csv-visualizerv1

# Instalar dependencias
npm install

# Configurar variables
cp .env.example .env.local
# Opcional: configura BD remota

# Desarrollo
npm run dev

# Build
npm run build
npm start
```

## 🐳 Docker

```bash
# Build
docker build -t json-csv-visualizer .

# Run
docker run -p 3000:3000 json-csv-visualizer
# O con docker-compose
docker-compose up -d
```

## 📁 Uso

1. **Carga archivos** → Sube JSON/CSV
2. **Conecta BD** → (Opcional) SQLite, PostgreSQL, etc.
3. **Explora datos** → Tablas, filtros, búsqueda
4. **Visualiza** → Gráficos y diagramas ER
5. **Exporta** → Descarga como CSV

## 📚 Documentación

→ **[joseangelalejo.github.io/json-csv-visualizerv1](https://joseangelalejo.github.io/json-csv-visualizerv1/)**

## 🔗 Enlaces

- 🌐 [Sitio en vivo](https://json-csv-visualizerv1.vercel.app)
- 📖 [Documentación](https://joseangelalejo.github.io/json-csv-visualizerv1/)
- ♻️ [GitHub Repo](https://github.com/joseangelalejo/json-csv-visualizerv1)
- 🐛 [Reportar bugs](https://github.com/joseangelalejo/json-csv-visualizerv1/issues)

```bash
git clone https://github.com/joseangelalejo/json-csv-visualizerv1.git
cd json-csv-visualizerv1
cp .env.example .env          # o `cp .env.example .env.local`
# Genera un JWT_SECRET fuerte (ejemplo):
#   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Pega ese valor en .env (JWT_SECRET) y, para dev, en NEXTAUTH_SECRET

docker compose up --build
```

Accede a `http://localhost` (o `http://localhost:80` si usas el proxy `nginx`)

### Opción 2: 💻 Desarrollo Local

```bash
git clone https://github.com/joseangelalejo/json-csv-visualizerv1.git
cd json-csv-visualizerv1
npm install
npm run dev
```

Abre `http://localhost:3000`

---

## 📖 Cómo Usar

### 1. 📁 Modo Archivo

- Haz clic en "📁 File Upload (JSON/CSV)"
- Selecciona tu archivo JSON o CSV
- ¡Explora la tabla y el gráfico automáticamente!

---

### 2. 🗄️ Modo Base de Datos

La aplicación ofrece dos formas de trabajar con bases de datos: **visualización sin SQL** e **IDE SQL interactivo**.

---

#### 2.1 Conectarse a una Base de Datos

Antes de explorar o ejecutar consultas, necesitas configurar una conexión:

1. Abre el panel lateral de **Conexiones** y haz clic en **Nueva conexión**.
2. Selecciona el tipo de base de datos: `SQLite`, `PostgreSQL`, `MySQL` o `MongoDB`.
3. Introduce los parámetros de conexión:

   | Motor      | Formato de conexión                               |
   |------------|---------------------------------------------------|
   | SQLite     | Ruta al archivo, ej. `/ruta/a/mi-base.db`         |
   | PostgreSQL | `postgresql://usuario:contraseña@host:5432/base`  |
   | MySQL      | Objeto con `host`, `user`, `password`, `database` |
   | MongoDB    | `mongodb://localhost:27017/base`                  |

4. Haz clic en **Probar conexión** para verificar que todo funciona.
5. Guarda la conexión con un nombre descriptivo — se almacena en el navegador para reutilizarla.

> Las conexiones guardadas aparecen en el árbol lateral. Puedes ocultar bases de datos de sistema desde las opciones del panel.

---

#### 2.2 Visualización de Bases de Datos (sin SQL)

Explora esquemas y datos sin escribir una sola línea de SQL — ideal para inspección rápida y análisis visual.

**Qué puedes hacer:**

- Navega el árbol de esquemas y tablas en el panel lateral.
- Haz clic en una tabla para abrir una **vista previa** de sus filas con paginación, ordenación, búsqueda y filtros por columna.
- Visualiza **diagramas ER automáticos** — las relaciones entre tablas se detectan automáticamente y se muestran como un grafo interactivo.
- Haz clic en cualquier columna para ver **estadísticas rápidas**: valores únicos, nulos, mínimo/máximo e histograma.
- Crea **gráficos visuales** (barra, línea, pastel) a partir de las columnas con un clic.
- Exporta cualquier resultado a **CSV** o cópialo al portapapeles.

**Flujo de uso:**

1. Selecciona una conexión guardada en el panel lateral.
2. Expande el árbol de esquemas y haz clic en una tabla.
3. Explora los datos en la vista tabular interactiva.
4. Usa el panel **ER** para ver relaciones y saltar a tablas relacionadas.
5. Haz clic en una columna para ver estadísticas y crear gráficos rápidos.
6. Exporta con el botón **Exportar CSV** en la cabecera de resultados.

> La vista de tablas es **de solo lectura por defecto** — no ejecuta DDL/DML sin confirmación explícita.

---

#### 2.3 IDE SQL Integrado

La aplicación incluye un editor SQL tipo **IDE** (basado en Monaco Editor) para escribir y ejecutar consultas directamente desde el navegador.

**Características del editor:**

- Resaltado de sintaxis SQL, **autocompletado** de tablas/columnas, formateo automático y atajos estilo VS Code.
- Ejecuta **selecciones de texto**, **sentencias individuales** o el **contenido completo** de la pestaña.
- Soporte para **múltiples sentencias** en una misma ejecución y la instrucción `USE <db>` en el servidor.
- Resultados por sentencia: tabla paginada con tiempo de ejecución, conteo de filas y opción de **exportar a CSV**.
- **Historial de consultas** y gestión de **snippets/scripts** reutilizables.
- Si Monaco no carga, hay un editor `textarea` como respaldo automático.

**Flujo de uso:**

1. Selecciona una conexión y base de datos en el panel de conexiones.
2. Escribe tu consulta SQL en el editor.
3. Ejecuta con `Ctrl/Cmd + Enter` (selección/sentencia) o con el botón **Ejecutar (▶)** (toda la pestaña).
4. Revisa los resultados en la tabla inferior — tiempo de ejecución, filas devueltas y posibles errores.
5. Exporta el resultado con el botón **Exportar CSV**.

**Atajos de teclado:**

| Atajo                  | Acción                                          |
|------------------------|-------------------------------------------------|
| `Ctrl/Cmd + Enter`     | Ejecutar selección o sentencia bajo el cursor   |
| `Ctrl/Cmd + Shift + F` | Formatear SQL                                   |
| `Ctrl/Cmd + /`         | Comentar / descomentar línea                    |
| `Ctrl/Cmd + D`         | Seleccionar siguiente ocurrencia (multi-cursor) |
| `Alt + ↑ / Alt + ↓`    | Mover línea arriba/abajo                        |
| `Ctrl/Cmd + Space`     | Activar sugerencias / autocompletado            |
| `Ctrl/Cmd + Shift + L` | Seleccionar todas las ocurrencias resaltadas    |

**Notas y buenas prácticas:**

- Evita ejecutar consultas destructivas (`DROP`, `DELETE`, `TRUNCATE`) en entornos de producción desde la UI.
- La ejecución de múltiples sentencias está gestionada por el servidor (parser + splitter) y muestra resultados por sentencia cuando procede.
- Usa `USE <base_de_datos>` para cambiar de base de datos sin cambiar la conexión.

---

## 🧪 Pruebas

### Probar Conexiones de Base de Datos

Para probar las conexiones sin configurar servidores reales, usa SQLite con el archivo de prueba incluido:

1. **SQLite (Recomendado para pruebas)**:
   - Tipo: `SQLite`
   - Connection String: `/tmp/test.db`
   - Contiene una tabla `users` con datos de ejemplo

2. **Otras Bases de Datos**:
   - **PostgreSQL**: `postgresql://user:password@localhost:5432/database`
   - **MySQL**: Config object con `host`, `user`, `password`, `database`
   - **MongoDB**: `mongodb://localhost:27017/database`

### 📊 Archivos de Prueba

- Archivo SQLite de prueba: `/tmp/test.db` (se crea automáticamente al ejecutar los tests)
- Contiene tabla `users` con columnas: `id`, `name`, `email`

### 🔍 Mensajes de Error Mejorados

Los errores de conexión proporcionan mensajes específicos:

- "SQLite database file does not exist"
- "Host not found. Check the hostname/IP address."
- "Access denied. Check username and password."
- "Database does not exist. Check database name."

### 🧪 Script de Pruebas Automáticas

```bash
./test-db-connections.sh
```

Este script probará:

- ✅ Conexión SQLite exitosa
- ❌ Conexión SQLite con archivo inexistente
- ❌ Conexión PostgreSQL con host inválido
- ❌ Conexión MySQL con configuración inválida

### 🔁 Pruebas E2E (Playwright)

```bash
# Preparar datos de prueba
npm run prepare:e2e

# Ejecutar la suite E2E
npm run test:e2e
```

Las pruebas usan `@playwright/test` y están configuradas en `tests/e2e/`.

### ⚙️ Variables de entorno

- `JWT_SECRET` (requerido): clave de firma JWT. Genera con:
  - `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` o `openssl rand -hex 64`
- `NEXTAUTH_SECRET`: en desarrollo puede/debe coincidir con `JWT_SECRET`.
- `ALLOWED_ORIGINS`, `USERS_DB_PATH`, `LOG_FILE` — ver `.env.example`.

> La pipeline de CI/Actions revisa `secrets.JWT_SECRET` y, si no existe, genera un secreto temporal para el job. Se recomienda añadir `JWT_SECRET` como secret en GitHub.

---

## 🔧 Tecnologías Utilizadas

**Frontend** — Next.js 16 + React 19 + TypeScript

**Styling** — Tailwind CSS + Gradientes

**Visualización** — Recharts + TanStack Table + React Flow

**Backend** — Next.js API Routes + Docker

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! 🌟

1. Fork el proyecto
2. Crea tu rama (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Ideas para Contribuciones

- ➕ Soporte para más tipos de bases de datos
- 🎨 Nuevos tipos de gráficos
- 🌍 Internacionalización (i18n)
- 📱 Mejoras en la UI móvil
- 🔒 Autenticación y permisos

---

## 🖥️ Despliegue en Producción

Para información detallada sobre cómo desplegar esta aplicación en producción con Docker, seguridad, monitoreo y acceso remoto, consulta el archivo [PRODUCTION_README.md](./PRODUCTION_README.md).

Este documento incluye:

- Configuración de Docker Compose para producción
- Configuración de nginx como proxy reverso
- Implementación de seguridad (JWT, rate limiting, headers de seguridad)
- Monitoreo y logging estructurado
- Configuración de acceso remoto
- Resolución de vulnerabilidades de dependencias

---

## 📜 Licencia

Este proyecto está licenciado bajo Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International — ver el archivo [LICENSE.md](./LICENSE.md) para más detalles.

---

Hecho con ❤️ y mucho 🧠

[Volver arriba ⬆️](#-jsoncsv-data-visualizer--web-ide)
