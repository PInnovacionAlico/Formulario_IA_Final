# 🎨 Formulario IA - Sistema de Generación de Diseños

Sistema completo de generación de diseños de empaques con Inteligencia Artificial.

## 🚀 Inicio Rápido

### 1. Clonar el repositorio

```bash
git clone https://github.com/PInnovacionAlico/Formulario_IA_Final.git
cd Formulario_IA_Final
```

### 2. Instalar dependencias

```bash
npm install
```

### 3. Configurar variables de entorno

Copia el archivo `.env.example` a `.env`:

```bash
cp .env.example .env
```

Edita el archivo `.env` y configura las siguientes variables:

#### 📋 Variables Requeridas

```bash
# Database & Storage
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_SERVICE_ROLE_KEY=tu_service_role_key

# Security (IMPORTANTE: Cambiar en producción)
JWT_SECRET=tu-secreto-jwt-seguro-aqui
```

**Generar JWT_SECRET seguro:**
```bash
node generate-jwt-secret.js
```

#### 🔧 Variables Opcionales

```bash
# Server
PORT=3000
NODE_ENV=production

# CORS (Recomendado para producción)
ALLOWED_ORIGINS=https://tudominio.com,https://www.tudominio.com

# Webhooks
WEBHOOK_API_KEY=tu-webhook-api-key
WEBHOOK_REGISTRO_USUARIO=https://tu-webhook.com/registro
PASSWORD_RESET_WEBHOOK_URL=https://tu-webhook.com/reset-password
WEBHOOK_AI_FORM=https://tu-webhook.com/ai-form
DISABLE_WEBHOOK=false
```

### 4. Iniciar el servidor

```bash
npm start
```

El servidor estará disponible en `http://localhost:3000`

---

## 📁 Estructura del Proyecto

```
Formulario_IA_Final/
├── public/                    # Archivos estáticos (HTML, CSS, JS)
│   ├── admin-dashboard.html   # Panel de administración
│   ├── dashboard.html         # Dashboard de usuario
│   ├── forms.html            # Formularios de diseño
│   ├── history.html          # Historial de diseños
│   ├── login.html            # Inicio de sesión
│   ├── register.html         # Registro de usuarios
│   ├── settings.html         # Configuración de cuenta
│   ├── shared-components.js  # Componentes compartidos
│   └── style.css             # Estilos globales
├── uploads/                   # Archivos temporales de uploads
├── temp_exports/             # Exportaciones temporales
├── server.js                 # Servidor Express principal
├── package.json              # Dependencias del proyecto
├── .env.example              # Ejemplo de configuración
├── generate-jwt-secret.js    # Generador de JWT_SECRET
└── SECURITY.md               # Documentación de seguridad
```

---

## 🔒 Seguridad

Este proyecto implementa las siguientes medidas de seguridad:

✅ **Rate Limiting** - Protección contra ataques de fuerza bruta
✅ **Helmet** - Headers de seguridad HTTP
✅ **XSS Protection** - Sanitización de inputs
✅ **File Validation** - Validación de archivos por firma (magic numbers)
✅ **JWT Authentication** - Tokens con expiración de 1 hora
✅ **CORS Configurado** - Control de acceso por origen
✅ **Password Hashing** - Bcrypt con 10 rounds
✅ **Email Verification** - Verificación de correo electrónico

Ver [SECURITY.md](./SECURITY.md) para más detalles.

---

## 🛠️ Tecnologías Utilizadas

### Backend
- **Node.js** + **Express** - Servidor web
- **Supabase** - Base de datos y storage
- **JWT** - Autenticación
- **Bcrypt** - Hashing de contraseñas
- **Multer** - Manejo de archivos
- **Sharp** - Procesamiento de imágenes
- **Helmet** - Security headers
- **express-rate-limit** - Rate limiting

### Frontend
- **HTML5** + **CSS3** + **JavaScript** - Vanilla JS
- **Fetch API** - Comunicación con backend

---

## 📊 Características

### Para Usuarios
- 📸 Subida de hasta 4 fotos de productos
- 🎨 Generación de diseños con IA
- 📁 Organización en carpetas
- 📱 Subida desde celular vía QR
- 📊 Historial de diseños generados
- 💳 Sistema de créditos (3 mensuales)
- ⚙️ Configuración de cuenta

### Para Administradores
- 👥 Gestión de usuarios
- 📊 Estadísticas del sistema
- 💳 Administración de créditos
- 🚫 Sistema de bans
- 📈 Panel de métricas

---

## 🔧 Scripts Disponibles

```bash
# Iniciar servidor
npm start

# Generar JWT_SECRET seguro
node generate-jwt-secret.js
```

---

## 🌍 Variables de Entorno

### Críticas (Requeridas)

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `SUPABASE_URL` | URL de tu proyecto Supabase | `https://xxx.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key de Supabase | `eyJhbGc...` |
| `JWT_SECRET` | Secreto para firmar JWT (min 32 chars) | `abc123...` |

### Seguridad (Recomendadas)

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `ALLOWED_ORIGINS` | Orígenes CORS permitidos | `*` |
| `NODE_ENV` | Entorno de ejecución | `development` |

### Webhooks (Opcionales)

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `DISABLE_WEBHOOK` | Deshabilitar webhooks | `false` |
| `WEBHOOK_API_KEY` | API Key para autenticación (header: x-api-key) | - |
| `WEBHOOK_REGISTRO_USUARIO` | Webhook de registro | - |
| `PASSWORD_RESET_WEBHOOK_URL` | Webhook de reset password | - |
| `WEBHOOK_AI_FORM` | Webhook de formulario IA | - |

**Nota:** Cuando se configura `WEBHOOK_API_KEY`, todas las llamadas a webhooks incluyen automáticamente el header `x-api-key` con este valor para autenticación.

---

## 📦 Despliegue en Producción

### Checklist Pre-Despliegue

- [ ] JWT_SECRET cambiado a valor aleatorio fuerte
- [ ] ALLOWED_ORIGINS configurado con dominios específicos
- [ ] NODE_ENV=production configurado
- [ ] Webhooks configurados (si se usan)
- [ ] HTTPS habilitado
- [ ] Variables de entorno configuradas en el servidor
- [ ] Backups de base de datos configurados

### Plataformas Soportadas

- ✅ Railway
- ✅ Heroku
- ✅ Vercel
- ✅ AWS
- ✅ DigitalOcean
- ✅ VPS

---

## 🐛 Solución de Problemas

### Error: "Missing required environment variables"

Asegúrate de que todas las variables críticas estén configuradas en `.env`:
```bash
SUPABASE_URL=...
SUPABASE_SERVICE_ROLE_KEY=...
JWT_SECRET=...
```

### Error: "Too many requests"

El rate limiting está activo. Espera 15 minutos o ajusta los límites en `server.js`.

### Webhooks no funcionan

Verifica que:
1. `DISABLE_WEBHOOK` no esté en `true`
2. Las URLs de webhook estén configuradas
3. Los endpoints webhook estén accesibles

---

## 📄 Licencia

MIT

---

## 👥 Soporte

Para reportar problemas o solicitar características:
- 📧 Email: soporte@alico-sa.com
- 🐛 Issues: GitHub Issues

---

**Desarrollado por Alico - Innovación en Empaques** 🎨
