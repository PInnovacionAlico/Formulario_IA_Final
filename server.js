require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const sharp = require('sharp');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { fileTypeFromBuffer } = require('file-type');

const app = express();
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// Security headers con helmet
// CSP más permisivo para permitir inline scripts necesarios para la funcionalidad
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"],
      scriptSrcAttr: ["'unsafe-inline'"], // Permite onclick y event handlers inline
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", process.env.SUPABASE_URL || "*"],
      fontSrc: ["'self'", "data:"],
      formAction: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configurado con origen específico
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'];
app.use(cors({
  origin: allowedOrigins[0] === '*' ? true : allowedOrigins,
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 intentos
  message: { error: 'Demasiados intentos. Por favor, intenta de nuevo en 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Solo cuenta intentos fallidos
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 requests
  message: { error: 'Demasiadas solicitudes. Por favor, intenta de nuevo más tarde.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 20, // 20 uploads por hora
  message: { error: 'Límite de subidas alcanzado. Intenta de nuevo en una hora.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Aplicar rate limiter general a todas las rutas API
app.use('/api/', generalLimiter);

// Supabase client (use service role key on server only)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Validate critical environment variables
const requiredEnvVars = {
  'SUPABASE_URL': supabaseUrl,
  'SUPABASE_SERVICE_ROLE_KEY': supabaseKey,
  'JWT_SECRET': process.env.JWT_SECRET
};

const missingVars = Object.entries(requiredEnvVars)
  .filter(([_, value]) => !value)
  .map(([key]) => key);

if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables!');
  Object.entries(requiredEnvVars).forEach(([key, value]) => {
    console.error(`${key}:`, value ? '✓ Set' : '✗ Missing');
  });
  console.error('\n⚠️  Please configure the missing variables in your .env file');
  process.exit(1);
}

// Validate webhooks are configured (warn only, don't exit)
const webhookVars = {
  'WEBHOOK_REGISTRO_USUARIO': process.env.WEBHOOK_REGISTRO_USUARIO,
  'PASSWORD_RESET_WEBHOOK_URL': process.env.PASSWORD_RESET_WEBHOOK_URL,
  'WEBHOOK_AI_FORM': process.env.WEBHOOK_AI_FORM,
  'WEBHOOK_API_KEY': process.env.WEBHOOK_API_KEY
};

const missingWebhooks = Object.entries(webhookVars)
  .filter(([_, value]) => !value)
  .map(([key]) => key);

if (missingWebhooks.length > 0 && process.env.DISABLE_WEBHOOK !== 'true') {
  console.warn('⚠️  Warning: Some webhook configuration is missing:');
  missingWebhooks.forEach(key => console.warn(`  - ${key}`));
  console.warn('Set DISABLE_WEBHOOK=true in .env to suppress this warning\n');
}

const supabase = createClient(supabaseUrl, supabaseKey);

console.log('✅ Environment variables validated successfully');
console.log('📊 Configuration:');
console.log(`  - Port: ${process.env.PORT || 3000}`);
console.log(`  - Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`  - Webhooks: ${process.env.DISABLE_WEBHOOK === 'true' ? 'Disabled' : 'Enabled'}`);
console.log(`  - CORS: ${process.env.ALLOWED_ORIGINS || '*'}\n`);

// helper: sanitize filename to avoid bad chars and path traversal
function sanitizeFilename(name) {
  if (!name) return '';
  // replace anything not alphanumeric, dot, underscore or dash
  return name.replace(/[^a-zA-Z0-9. _-]/g, '_').replace(/\s+/g, '_').slice(0, 200);
}

// Authentication middleware: verify JWT and add userId to req
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    
    // Check if user is banned
    supabase
      .from('users')
      .select('banned, banned_reason')
      .eq('id', req.userId)
      .single()
      .then(({ data: user, error }) => {
        if (error) {
          return res.status(500).json({ error: 'Error checking user status' });
        }
        if (user && user.banned) {
          return res.status(403).json({ 
            error: 'Account banned', 
            message: user.banned_reason || 'Your account has been permanently banned.',
            userBanned: true
          });
        }
        next();
      })
      .catch(() => {
        return res.status(500).json({ error: 'Error checking user status' });
      });
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

// Admin authentication middleware: verify JWT and check if user is admin
async function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    
    // Check if user is admin and not banned
    const { data: user, error } = await supabase
      .from('users')
      .select('is_admin, is_super_admin, banned, banned_reason')
      .eq('id', req.userId)
      .single();
    
    if (error) throw error;
    
    if (user && user.banned) {
      return res.status(403).json({ 
        error: 'Account banned', 
        message: user.banned_reason || 'Your account has been permanently banned.',
        userBanned: true
      });
    }
    
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    
    // Attach super admin status to request
    req.isSuperAdmin = user.is_super_admin || false;
    
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

function getWebhookUrlFromReq(req) {
  // Allow global disable via env var for easy testing/rollback
  if (process.env.DISABLE_WEBHOOK && process.env.DISABLE_WEBHOOK.toLowerCase() === 'true') return null;
  // Header takes precedence, otherwise use env
  return req.headers['x-webhook-url'] || process.env.WEBHOOK_URL;
}

function getPasswordResetWebhookUrl(req) {
  // Allow global disable via env var for easy testing/rollback
  if (process.env.DISABLE_WEBHOOK && process.env.DISABLE_WEBHOOK.toLowerCase() === 'true') return null;
  // Use specific password reset webhook from env
  return req.headers['x-webhook-url'] || process.env.PASSWORD_RESET_WEBHOOK_URL;
}

async function postToWebhook(webhookUrl, payload, headers = {}) {
  if (!webhookUrl) throw new Error('No webhook URL configured');
  
  // Agregar x-api-key header si está configurado
  const webhookHeaders = {
    'Content-Type': 'application/json',
    ...headers
  };
  
  if (process.env.WEBHOOK_API_KEY) {
    webhookHeaders['x-api-key'] = process.env.WEBHOOK_API_KEY;
  }
  
  const res = await axios.post(webhookUrl, payload, { headers: webhookHeaders });
  return res.data;
}

// Login endpoint: validate credentials and return JWT
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  try {
    const { data: user, error } = await supabase.from('users').select('id, name, email, password_hash, is_admin, email_verified, credits, credits_last_reset, banned, banned_reason').eq('email', email).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(401).json({ error: 'Correo no registrado o contraseña incorrecta' });

    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Correo no registrado o contraseña incorrecta' });

    // Check if user is banned
    if (user.banned) {
      return res.status(403).json({ 
        error: 'Account banned', 
        message: user.banned_reason || 'Your account has been permanently banned. Please contact support for more information.',
        userBanned: true,
        banned_at: user.banned_at
      });
    }

    // Check if email is verified
    if (!user.email_verified) {
      return res.status(403).json({ 
        error: 'Email not verified', 
        message: 'Por favor verifica tu correo electrónico antes de iniciar sesión. Revisa tu bandeja de entrada para encontrar el enlace de verificación.',
        emailNotVerified: true 
      });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin || false, is_super_admin: user.is_super_admin || false } });
  } catch (err) {
    console.error('login error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.post('/api/register', async (req, res) => {
  const { name, email, password, acceptedTerms } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email and password are required' });

  if (!acceptedTerms) return res.status(400).json({ error: 'you must accept the terms and conditions' });

  if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });

  try {
    // Generate verification token
    const verificationToken = uuidv4();
    const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const password_hash = bcrypt.hashSync(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ 
        name, 
        email, 
        password_hash,
        email_verified: false,
        verification_token: verificationToken,
        verification_token_expiry: verificationTokenExpiry.toISOString()
      }])
      .select('*')
      .single();

    if (error) {
      // unique violation handling
      if (error.code === '23505' || (error.message && error.message.toLowerCase().includes('duplicate'))) {
        return res.status(400).json({ error: 'email already exists' });
      }
      throw error;
    }

    // Generate verification link
    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    const verificationLink = `${baseUrl}/verify-email.html?token=${verificationToken}`;

    // Send to webhook for email notification
    const webhookUrl = process.env.WEBHOOK_REGISTRO_USUARIO;
    const payload = { 
      action: 'register', 
      data: { 
        id: data.id, 
        name: data.name, 
        email: data.email, 
        created_at: data.created_at,
        verification_link: verificationLink
      } 
    };
    
    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
        // do not fail registration because webhook failed
      }
    }

    res.json({ ok: true, id: data.id, message: 'Please check your email to verify your account' });
  } catch (err) {
    console.error('register error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.post('/api/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body || {};
  if (!email || !oldPassword || !newPassword) return res.status(400).json({ error: 'email, oldPassword and newPassword are required' });

  if (newPassword.length < 8) return res.status(400).json({ error: 'newPassword must be at least 8 characters' });

  try {
    const { data: user, error: fetchErr } = await supabase.from('users').select('id, name, email, password_hash').eq('email', email).maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!user) return res.status(404).json({ error: 'user not found' });

    const ok = bcrypt.compareSync(oldPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'old password incorrect' });

    const newHash = bcrypt.hashSync(newPassword, 10);
    const { data, error: upErr } = await supabase.from('users').update({ password_hash: newHash }).eq('id', user.id).select('id, email').single();
    if (upErr) throw upErr;

    const webhookUrl = getWebhookUrlFromReq(req);
    const payload = { action: 'change-password', data: { id: data.id, email: data.email, updated_at: new Date().toISOString() } };
    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
      }
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('change-password error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Verify email with token
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.status(400).json({ error: 'Verification token is required' });
  }

  try {
    // Find user with this verification token
    const { data: user, error: fetchErr } = await supabase
      .from('users')
      .select('*')
      .eq('verification_token', token)
      .maybeSingle();

    if (fetchErr) throw fetchErr;

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    // Check if already verified
    if (user.email_verified) {
      return res.json({ ok: true, message: 'Email already verified', alreadyVerified: true });
    }

    // Check if token has expired
    if (user.verification_token_expiry && new Date(user.verification_token_expiry) < new Date()) {
      return res.status(400).json({ error: 'Verification token has expired. Please request a new one.' });
    }

    // Update user as verified
    const { data: updatedUser, error: updateErr } = await supabase
      .from('users')
      .update({ 
        email_verified: true,
        verification_token: null,
        verification_token_expiry: null
      })
      .eq('id', user.id)
      .select('*')
      .single();

    if (updateErr) throw updateErr;

    res.json({ 
      ok: true, 
      message: 'Email verified successfully!',
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email
      }
    });
  } catch (err) {
    console.error('verify-email error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Resend verification email
app.post('/api/resend-verification', async (req, res) => {
  const { email } = req.body || {};
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Find user by email
    const { data: user, error: fetchErr } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (fetchErr) throw fetchErr;

    if (!user) {
      // Don't reveal if user exists or not (security best practice)
      return res.json({ ok: true, message: 'If the email exists, a verification link will be sent' });
    }

    // Check if already verified
    if (user.email_verified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    // Generate new verification token
    const verificationToken = uuidv4();
    const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Update user with new token
    const { error: updateErr } = await supabase
      .from('users')
      .update({ 
        verification_token: verificationToken,
        verification_token_expiry: verificationTokenExpiry.toISOString()
      })
      .eq('id', user.id);

    if (updateErr) throw updateErr;

    // Generate verification link
    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    const verificationLink = `${baseUrl}/verify-email.html?token=${verificationToken}`;

    // Send to webhook for email notification
    const webhookUrl = process.env.WEBHOOK_REGISTRO_USUARIO;
    const payload = { 
      action: 'resend-verification', 
      data: { 
        id: user.id, 
        name: user.name, 
        email: user.email, 
        verification_link: verificationLink
      } 
    };
    
    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
        // do not fail because webhook failed
      }
    }

    res.json({ ok: true, message: 'Verification email sent successfully' });
  } catch (err) {
    console.error('resend-verification error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Forgot password: generates reset token and sends to webhook
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email is required' });

  try {
    // Check if user exists
    const { data: user, error: fetchErr } = await supabase.from('users').select('id, name, email, email_verified').eq('email', email).maybeSingle();
    if (fetchErr) throw fetchErr;
    
    // Don't reveal if user exists or not (security best practice)
    if (!user) {
      return res.json({ ok: true, message: 'If the email exists, a reset link will be sent' });
    }

    // Generate reset token (valid for 1 hour)
    const resetToken = uuidv4();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour from now

    // Store token in database
    const { error: tokenErr } = await supabase.from('password_reset_tokens').insert([{
      user_id: user.id,
      token: resetToken,
      expires_at: expiresAt,
      used: false
    }]);
    if (tokenErr) throw tokenErr;

    // Construct reset link
    const resetLink = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}`;

    // Send to webhook for email delivery
    const webhookUrl = getPasswordResetWebhookUrl(req);
    const payload = {
      action: 'forgot-password',
      data: {
        email: user.email,
        name: user.name,
        resetLink: resetLink,
        expiresAt: expiresAt
      }
    };

    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
        // Continue even if webhook fails
      }
    }

    res.json({ ok: true, message: 'If the email exists, a reset link will be sent' });
  } catch (err) {
    console.error('forgot-password error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Reset password: validates token and updates password
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'token and newPassword are required' });

  if (newPassword.length < 8) return res.status(400).json({ error: 'newPassword must be at least 8 characters' });

  try {
    // Find valid token
    const { data: resetToken, error: tokenErr } = await supabase
      .from('password_reset_tokens')
      .select('*')
      .eq('token', token)
      .eq('used', false)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();

    if (tokenErr) throw tokenErr;
    if (!resetToken) return res.status(400).json({ error: 'Invalid or expired token' });

    // Update password
    const newHash = bcrypt.hashSync(newPassword, 10);
    const { error: updateErr } = await supabase
      .from('users')
      .update({ password_hash: newHash })
      .eq('id', resetToken.user_id);
    
    if (updateErr) throw updateErr;

    // Mark token as used
    const { error: markErr } = await supabase
      .from('password_reset_tokens')
      .update({ used: true })
      .eq('id', resetToken.id);
    
    if (markErr) throw markErr;

    // Send webhook notification
    const { data: user } = await supabase.from('users').select('id, email, name').eq('id', resetToken.user_id).single();
    const webhookUrl = getWebhookUrlFromReq(req);
    const payload = {
      action: 'password-reset-completed',
      data: {
        id: user.id,
        email: user.email,
        name: user.name,
        reset_at: new Date().toISOString()
      }
    };

    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
      }
    }

    res.json({ ok: true, message: 'Password reset successful' });
  } catch (err) {
    console.error('reset-password error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Update user profile (name and/or email)
app.post('/api/update-profile', authenticate, async (req, res) => {
  const { name, email } = req.body || {};
  
  // At least one field must be provided
  if (!name && !email) {
    return res.status(400).json({ error: 'At least one field (name or email) is required' });
  }

  try {
    const userId = req.user.id;
    const updateData = {};
    
    // Add fields to update
    if (name) {
      if (name.trim().length === 0) {
        return res.status(400).json({ error: 'Name cannot be empty' });
      }
      updateData.name = name.trim();
    }
    
    if (email) {
      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      
      // Check if email is already taken by another user
      const { data: existingUser, error: checkErr } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .neq('id', userId)
        .maybeSingle();
      
      if (checkErr) throw checkErr;
      
      if (existingUser) {
        return res.status(400).json({ error: 'Email already in use by another user' });
      }
      
      updateData.email = email.toLowerCase().trim();
    }

    // Update user in database
    const { data: updatedUser, error: updateErr } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', userId)
      .select('id, name, email, credits, is_admin, is_super_admin, created_at')
      .single();
    
    if (updateErr) throw updateErr;

    // Send webhook notification
    const webhookUrl = getWebhookUrlFromReq(req);
    const payload = {
      action: 'profile-updated',
      data: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        updated_fields: Object.keys(updateData),
        updated_at: new Date().toISOString()
      }
    };

    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
      }
    }

    res.json({ 
      ok: true, 
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (err) {
    console.error('update-profile error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Generate temporary upload token for mobile QR upload
app.post('/api/generate-upload-token', authenticate, async (req, res) => {
  try {
    // Generate a temporary token that expires in 30 minutes
    const uploadToken = jwt.sign(
      { 
        userId: req.userId,
        type: 'mobile-upload'
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '30m' }
    );
    
    res.json({ 
      ok: true, 
      uploadToken,
      expiresIn: 30 * 60 // 30 minutes in seconds
    });
  } catch (err) {
    console.error('Error generating upload token:', err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Mobile upload endpoint: uses temporary token from QR code
app.post('/api/mobile-upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'file is required' });
  
  // Get token from query or body
  const uploadToken = req.query.token || req.body.token;
  if (!uploadToken) {
    return res.status(401).json({ error: 'Upload token required' });
  }
  
  try {
    // Verify the upload token
    const decoded = jwt.verify(uploadToken, process.env.JWT_SECRET);
    if (decoded.type !== 'mobile-upload') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    
    const userId = decoded.userId;
    
    // Verificar límite de 4 fotos por usuario (solo fotos subidas, no generadas por IA)
    const { data: existingUploads, error: countErr } = await supabase
      .from('uploads')
      .select('id', { count: 'exact', head: false })
      .eq('owner_id', userId)
      .eq('bucket_name', 'uploads'); // Solo contar fotos subidas, no las generadas
    
    if (countErr) throw countErr;
    
    if (existingUploads && existingUploads.length >= 4) {
      // Eliminar archivo temporal
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(400).json({ 
        error: 'Límite de fotos alcanzado',
        message: 'Solo puedes tener un máximo de 4 fotos subidas. Elimina algunas fotos antes de subir nuevas. (Las imágenes generadas por IA no cuentan en este límite)',
        current_count: existingUploads.length,
        max_limit: 4
      });
    }
    
    // Same upload logic as regular upload
    const safeName = sanitizeFilename(file.originalname);
    const unique = uuidv4();
    const prefix = String(userId);
    const pathInBucket = `uploads/${prefix}/${unique}-${safeName}`;
    const thumbnailPath = `uploads/${prefix}/thumb-${unique}-${safeName}`;
    
    const fileBuffer = fs.readFileSync(file.path);

    const { data: uploadData, error: uploadErr } = await supabase.storage.from('uploads').upload(pathInBucket, fileBuffer, {
      contentType: file.mimetype,
      upsert: false
    });
    if (uploadErr) throw uploadErr;

    const thumbnailBuffer = await sharp(fileBuffer)
      .resize(400, null, { withoutEnlargement: true, fit: 'inside' })
      .jpeg({ quality: 70 })
      .toBuffer();

    const { error: thumbErr } = await supabase.storage.from('uploads').upload(thumbnailPath, thumbnailBuffer, {
      contentType: 'image/jpeg',
      upsert: false
    });
    if (thumbErr) console.warn('thumbnail upload warning', thumbErr.message);

    const { data: urlData, error: urlErr } = await supabase.storage.from('uploads').createSignedUrl(pathInBucket, 24 * 60 * 60);
    if (urlErr) throw urlErr;
    
    const { data: thumbUrlData } = await supabase.storage.from('uploads').createSignedUrl(thumbnailPath, 24 * 60 * 60);

    const folder = req.body.folder || null;
    const customName = req.body.customName || file.originalname;

    const { data: dbData, error: dbErr } = await supabase.from('uploads').insert({
      owner_id: userId,
      filename: safeName,
      path: pathInBucket,
      thumbnail_path: thumbnailPath,
      folder: folder,
      custom_name: customName
    }).select().single();
    if (dbErr) throw dbErr;

    fs.unlinkSync(file.path);

    res.json({ 
      ok: true, 
      upload: {
        id: dbData.id,
        filename: dbData.filename,
        customName: dbData.custom_name,
        folder: dbData.folder,
        signedUrl: urlData.signedUrl,
        thumbnailUrl: thumbUrlData?.signedUrl
      }
    });
  } catch (err) {
    console.error('Mobile upload error:', err);
    if (file && fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Upload endpoint: accepts single file field 'file' (protected)
app.post('/api/upload', authenticate, uploadLimiter, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'file is required' });

  try {
    // Validar tipo de archivo por MIME type
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png'];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(400).json({ error: 'Tipo de archivo no permitido. Solo se permiten imágenes JPG, JPEG y PNG.' });
    }

    // Validar tamaño máximo (5MB)
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (file.size > maxSize) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(400).json({ error: 'Archivo demasiado grande. Tamaño máximo: 5MB.' });
    }

    // Leer archivo y validar firma del archivo (magic numbers)
    const fileBuffer = fs.readFileSync(file.path);
    const detectedType = await fileTypeFromBuffer(fileBuffer);
    
    if (!detectedType || !allowedMimeTypes.includes(detectedType.mime)) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(400).json({ error: 'Archivo corrupto o tipo inválido. Solo se permiten imágenes JPG, JPEG y PNG reales.' });
    }

    // Verificar límite de 4 fotos por usuario (solo fotos subidas, no generadas por IA)
    const { data: existingUploads, error: countErr } = await supabase
      .from('uploads')
      .select('id', { count: 'exact', head: false })
      .eq('owner_id', req.userId)
      .eq('bucket_name', 'uploads'); // Solo contar fotos subidas, no las generadas
    
    if (countErr) throw countErr;
    
    if (existingUploads && existingUploads.length >= 4) {
      // Eliminar archivo temporal
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(400).json({ 
        error: 'Límite de fotos alcanzado',
        message: 'Solo puedes tener un máximo de 4 fotos subidas. Elimina algunas fotos antes de subir nuevas. (Las imágenes generadas por IA no cuentan en este límite)',
        current_count: existingUploads.length,
        max_limit: 4
      });
    }
    
    // upload to Supabase storage
    const safeName = sanitizeFilename(file.originalname);
    const unique = uuidv4();
    const prefix = String(req.userId); // use authenticated userId
    const pathInBucket = `uploads/${prefix}/${unique}-${safeName}`;
    const thumbnailPath = `uploads/${prefix}/thumb-${unique}-${safeName}`;

    // Upload original image
    const { data: uploadData, error: uploadErr } = await supabase.storage.from('uploads').upload(pathInBucket, fileBuffer, {
      contentType: file.mimetype,
      upsert: false
    });
    if (uploadErr) throw uploadErr;

    // Generate and upload thumbnail (max 400px width, quality 70%)
    const thumbnailBuffer = await sharp(fileBuffer)
      .resize(400, null, { withoutEnlargement: true, fit: 'inside' })
      .jpeg({ quality: 70 })
      .toBuffer();

    const { error: thumbErr } = await supabase.storage.from('uploads').upload(thumbnailPath, thumbnailBuffer, {
      contentType: 'image/jpeg',
      upsert: false
    });
    if (thumbErr) console.warn('thumbnail upload warning', thumbErr.message);

    // create signed URL (24 hours for dashboard usage)
    const { data: urlData, error: urlErr } = await supabase.storage.from('uploads').createSignedUrl(pathInBucket, 24 * 60 * 60);
    if (urlErr) console.warn('signed url warning', urlErr.message || urlErr);

    // save metadata in uploads table with authenticated owner_id
    const folder = req.body.folder || 'Sin carpeta';
    const { data: dbUpload, error: dbErr } = await supabase.from('uploads').insert([{
      owner_id: req.userId,
      owner_email: req.body.ownerEmail || null,
      filename: file.originalname,
      path: pathInBucket,
      thumbnail_path: thumbnailPath,
      mimetype: file.mimetype,
      size: file.size,
      custom_name: null,
      folder: folder
    }]).select('*').single();
    if (dbErr) throw dbErr;

    // remove temporary file
    fs.unlink(file.path, () => {});

    const payload = { action: 'upload', data: { id: dbUpload.id, filename: dbUpload.filename, size: dbUpload.size, mimetype: dbUpload.mimetype, url: urlData?.signedUrl || null } };
    const webhookUrl = getWebhookUrlFromReq(req);
    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
      }
    }

    res.json({ ok: true, upload: dbUpload, signedUrl: urlData?.signedUrl });
  } catch (err) {
    console.error('upload error FULL:', err);
    console.error('upload error message:', err.message);
    console.error('upload error stack:', err.stack);
    if (file && file.path) {
      fs.unlink(file.path, () => {});
    }
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Cache de signed URLs en memoria (expira cada 20 horas)
const urlCache = new Map();
const URL_CACHE_DURATION = 20 * 60 * 60 * 1000; // 20 horas en ms

function getCachedUrl(key) {
  const cached = urlCache.get(key);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.url;
  }
  urlCache.delete(key);
  return null;
}

function setCachedUrl(key, url) {
  urlCache.set(key, {
    url,
    expiresAt: Date.now() + URL_CACHE_DURATION
  });
}

// Limpiar caché cada hora
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of urlCache.entries()) {
    if (now >= value.expiresAt) {
      urlCache.delete(key);
    }
  }
}, 60 * 60 * 1000);

// List user uploads (protected) - OPTIMIZADO PARA REDUCIR EGRESS
app.get('/api/uploads', authenticate, async (req, res) => {
  try {
    // Solo seleccionar los campos necesarios (no todo con *)
    const { data, error } = await supabase
      .from('uploads')
      .select('id, filename, custom_name, mimetype, size, folder, path, thumbnail_path, bucket_name, created_at')
      .eq('owner_id', req.userId)
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    
    // Contar solo fotos subidas por el usuario (sin IA)
    const userPhotosCount = data.filter(u => u.folder !== 'AI Generated').length;

    // Generar signed URLs con caché para reducir llamadas a Supabase Storage
    const uploadsWithUrls = await Promise.all(data.map(async (upload) => {
      const bucketName = upload.bucket_name || 'uploads';
      
      // Intentar obtener del caché
      let signedUrl = getCachedUrl(`${bucketName}:${upload.path}`);
      let thumbnailUrl = null;
      
      // Si no está en caché, generar nueva signed URL
      if (!signedUrl) {
        const { data: urlData } = await supabase.storage.from(bucketName).createSignedUrl(upload.path, 24 * 60 * 60);
        signedUrl = urlData?.signedUrl || null;
        if (signedUrl) setCachedUrl(`${bucketName}:${upload.path}`, signedUrl);
      }
      
      // Thumbnail con caché
      if (upload.thumbnail_path) {
        thumbnailUrl = getCachedUrl(`uploads:${upload.thumbnail_path}`);
        if (!thumbnailUrl) {
          const { data: thumbData } = await supabase.storage.from('uploads').createSignedUrl(upload.thumbnail_path, 24 * 60 * 60);
          thumbnailUrl = thumbData?.signedUrl || null;
          if (thumbnailUrl) setCachedUrl(`uploads:${upload.thumbnail_path}`, thumbnailUrl);
        }
      }
      
      return { 
        id: upload.id,
        filename: upload.filename,
        custom_name: upload.custom_name,
        mimetype: upload.mimetype,
        size: upload.size,
        folder: upload.folder,
        created_at: upload.created_at,
        signedUrl,
        thumbnailUrl
      };
    }));

    res.json({ ok: true, uploads: uploadsWithUrls, userPhotosCount });
  } catch (err) {
    console.error('list uploads error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get user folders (works with both regular auth and mobile upload token)
app.get('/api/folders', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;
    
    const { data, error } = await supabase
      .from('uploads')
      .select('folder')
      .eq('owner_id', userId);
    
    if (error) throw error;
    
    // Extract unique folders
    const folders = [...new Set(data.map(u => u.folder).filter(Boolean))];
    folders.sort();
    
    res.json({ ok: true, folders });
  } catch (err) {
    console.error('Get folders error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Update upload metadata (rename/folder) (protected)
app.patch('/api/uploads/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { customName, folder } = req.body || {};

  try {
    // verify ownership
    const { data: upload, error: fetchErr } = await supabase.from('uploads').select('*').eq('id', id).maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!upload) return res.status(404).json({ error: 'Upload not found' });
    if (upload.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden: not owner' });

    // update fields
    const updates = {};
    if (customName !== undefined) updates.custom_name = customName;
    if (folder !== undefined) updates.folder = folder || 'Sin carpeta';

    const { data, error: upErr } = await supabase.from('uploads').update(updates).eq('id', id).select('*').single();
    if (upErr) throw upErr;

    res.json({ ok: true, upload: data });
  } catch (err) {
    console.error('update upload error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Update upload (protected) - for changing folder or custom_name
app.put('/api/uploads/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { folder, custom_name } = req.body || {};

  try {
    // verify ownership
    const { data: upload, error: fetchErr } = await supabase.from('uploads').select('*').eq('id', id).maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!upload) return res.status(404).json({ error: 'Upload not found' });
    if (upload.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden: not owner' });

    // build update object
    const updates = {};
    if (folder !== undefined) updates.folder = folder;
    if (custom_name !== undefined) updates.custom_name = custom_name;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    // update in DB
    const { data, error: updateErr } = await supabase
      .from('uploads')
      .update(updates)
      .eq('id', id)
      .select('*')
      .single();
    
    if (updateErr) throw updateErr;

    res.json({ ok: true, upload: data });
  } catch (err) {
    console.error('update upload error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Delete upload (protected)
app.delete('/api/uploads/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    // verify ownership
    const { data: upload, error: fetchErr } = await supabase.from('uploads').select('*').eq('id', id).maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!upload) return res.status(404).json({ error: 'Upload not found' });
    if (upload.owner_id !== req.userId) return res.status(403).json({ error: 'Forbidden: not owner' });

    // Determinar el bucket correcto
    const bucketName = upload.bucket_name || 'uploads';
    
    // delete from storage (both original and thumbnail)
    const filesToDelete = [upload.path];
    if (upload.thumbnail_path) {
      filesToDelete.push(upload.thumbnail_path);
    }
    
    const { error: delErr } = await supabase.storage.from(bucketName).remove(filesToDelete);
    if (delErr) console.warn('storage delete warning', delErr.message || delErr);

    // delete from DB
    const { error: dbDelErr } = await supabase.from('uploads').delete().eq('id', id);
    if (dbDelErr) throw dbDelErr;

    res.json({ ok: true, message: 'Upload deleted' });
  } catch (err) {
    console.error('delete upload error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get user credits
app.get('/api/credits', authenticate, async (req, res) => {
  try {
    const { data: userCredits, error } = await supabase
      .from('users')
      .select('credits, credits_last_reset')
      .eq('id', req.userId)
      .single();
    
    if (error) throw error;

    // Check if credits need to be reset
    const lastReset = new Date(userCredits.credits_last_reset);
    const now = new Date();
    const monthsSinceReset = (now.getFullYear() - lastReset.getFullYear()) * 12 + 
                              (now.getMonth() - lastReset.getMonth());
    
    let credits = userCredits.credits;
    let resetDate = lastReset;
    
    if (monthsSinceReset >= 1) {
      // Reset credits
      const { error: resetErr } = await supabase
        .from('users')
        .update({ 
          credits: 3, 
          credits_last_reset: now.toISOString() 
        })
        .eq('id', req.userId);
      
      if (!resetErr) {
        credits = 3;
        resetDate = now;
      }
    }

    // Calculate next reset date (first day of next month)
    const nextReset = new Date(resetDate.getFullYear(), resetDate.getMonth() + 1, 1);

    res.json({ 
      ok: true, 
      credits,
      nextReset: nextReset.toISOString(),
      lastReset: resetDate.toISOString()
    });
  } catch (err) {
    console.error('get credits error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Submit form endpoint: generates temporary URL and sends to webhook
// ⚠️ IMPORTANT: URL expires in 5 minutes to minimize Supabase bandwidth usage
// The webhook receiver MUST download the image immediately upon receiving this payload
app.post('/api/submit-form', authenticate, async (req, res) => {
  const { user_photo, form_type, product_id, market_sector, product_description, logo_display_preference, ...formData } = req.body || {};
  
  // Extract photo_id from user_photo object
  const photo_id = user_photo?.id;
  
  if (!photo_id) {
    return res.status(400).json({ error: 'user_photo with id is required' });
  }

  // Validate form_type if provided
  const validFormTypes = ['termoformado', 'doypack', 'flowpack'];
  if (form_type && !validFormTypes.includes(form_type)) {
    return res.status(400).json({ error: 'Invalid form_type' });
  }

  try {
    // === CHECK AND RESET CREDITS ===
    const { data: userCredits, error: creditsErr } = await supabase
      .from('users')
      .select('credits, credits_last_reset')
      .eq('id', req.userId)
      .single();
    
    if (creditsErr) throw creditsErr;

    // Check if credits need to be reset (monthly)
    const lastReset = new Date(userCredits.credits_last_reset);
    const now = new Date();
    const monthsSinceReset = (now.getFullYear() - lastReset.getFullYear()) * 12 + 
                              (now.getMonth() - lastReset.getMonth());
    
    let currentCredits = userCredits.credits;
    
    if (monthsSinceReset >= 1) {
      // Reset credits to 3
      const { error: resetErr } = await supabase
        .from('users')
        .update({ 
          credits: 3, 
          credits_last_reset: now.toISOString() 
        })
        .eq('id', req.userId);
      
      if (resetErr) console.error('Error resetting credits:', resetErr);
      currentCredits = 3;
    }

    // Check if user has credits
    if (currentCredits <= 0) {
      return res.status(403).json({ 
        error: 'No tienes créditos disponibles',
        credits: 0,
        nextReset: new Date(lastReset.getFullYear(), lastReset.getMonth() + 1, 1).toISOString()
      });
    }

    // Deduct one credit
    const { error: deductErr } = await supabase
      .from('users')
      .update({ credits: currentCredits - 1 })
      .eq('id', req.userId);
    
    if (deductErr) throw deductErr;
    // Verify ownership and get photo details
    const { data: upload, error: fetchErr } = await supabase
      .from('uploads')
      .select('*')
      .eq('id', photo_id)
      .maybeSingle();
    
    if (fetchErr) throw fetchErr;
    if (!upload) return res.status(404).json({ error: 'Photo not found' });
    if (upload.owner_id !== req.userId) {
      return res.status(403).json({ error: 'Forbidden: not owner of this photo' });
    }

    // Generate temporary URL with 5 minutes expiration
    const fiveMinutesInSeconds = 5 * 60; // 300 seconds
    const { data: urlData, error: urlErr } = await supabase.storage
      .from('uploads')
      .createSignedUrl(upload.path, fiveMinutesInSeconds);
    
    if (urlErr) throw urlErr;
    if (!urlData?.signedUrl) {
      throw new Error('Failed to generate public URL');
    }

    // Get user info
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, name, email')
      .eq('id', req.userId)
      .single();
    
    if (userErr) console.warn('User fetch warning:', userErr.message);

    // Get product info and public image URL if product_id is provided
    let productInfo = null;
    console.log('🔍 product_id recibido:', product_id, 'tipo:', typeof product_id);
    if (product_id) {
      const { data: product, error: productErr } = await supabase
        .from('products')
        .select('id, name, category, image_path')
        .eq('id', product_id)
        .single();
      
      console.log('📦 Producto encontrado:', product);
      console.log('❌ Error al buscar producto:', productErr);
      
      if (!productErr && product) {
        // Get public URL for product image (5 minutes validity)
        const { data: productUrlData } = await supabase.storage
          .from('products')
          .createSignedUrl(product.image_path, fiveMinutesInSeconds);
        
        productInfo = {
          id: product.id,
          name: product.name,
          category: product.category,
          image_url: productUrlData?.signedUrl || null
        };
      }
    }

    // Variable to store AI image ID
    let aiImageId = null;
    
    // Prepare webhook payload
    const webhookPayload = {
      action: 'form_submitted',
      timestamp: new Date().toISOString(),
      form_type: form_type || null,
      user: user ? {
        id: user.id,
        name: user.name,
        email: user.email
      } : null,
      product: productInfo,
      user_photo: {
        id: upload.id,
        url: urlData.signedUrl, // 5-minute temporary URL to user's uploaded image
        filename: upload.filename,
        custom_name: upload.custom_name,
        folder: upload.folder,
        mimetype: upload.mimetype,
        size: upload.size,
        created_at: upload.created_at
      },
      market_sector: market_sector || null,
      product_description: product_description || null,
      logo_display_preference: logo_display_preference || null,
      ...formData // Expand all additional form fields at root level
    };

    // Send to Alico webhook
    const webhookUrl = process.env.WEBHOOK_AI_FORM;
    let webhookSent = false;
    let webhookStatus = null;
    let errorMessage = null;
    let generatedImageUrl = null;
    
    // Guardar submission inicial sin esperar el webhook
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now
    const { data: pendingSubmission } = await supabase.from('form_submissions').insert([{
      user_id: req.userId,
      photo_id: photo_id,
      form_type: form_type || null,
      product_id: product_id || null,
      market_sector: market_sector || null,
      product_description: product_description || null,
      logo_display_preference: logo_display_preference || null,
      success: false, // Se actualizará cuando complete el webhook
      webhook_sent: false,
      webhook_url: webhookUrl,
      form_data: formData,
      completed_at: null // Se actualizará cuando complete
    }]).select('id').single();
    
    const submissionId = pendingSubmission?.id;
    
    // Responder inmediatamente al usuario sin esperar el webhook
    res.json({ 
      ok: true, 
      message: 'Form submitted successfully. Image generation in progress.',
      submission_id: submissionId,
      webhook_sent: false,
      status: 'processing'
    });
    
    // Procesar webhook en background (no bloquea la respuesta)
    (async () => {
      try {
        // Usar postToWebhook para incluir x-api-key header
        const webhookResponse = await axios.post(webhookUrl, webhookPayload, {
          headers: {
            'Content-Type': 'application/json',
            ...(process.env.WEBHOOK_API_KEY && { 'x-api-key': process.env.WEBHOOK_API_KEY })
          },
          timeout: 60000, // 60 segundos timeout (45s generación + 15s margen)
          maxContentLength: 50 * 1024 * 1024, // 50MB max response
          maxBodyLength: 50 * 1024 * 1024
        });
      
      console.log('Webhook sent successfully:', webhookResponse.status);
      console.log('Webhook response data:', webhookResponse.data);
      console.log('Webhook response type:', typeof webhookResponse.data);
      console.log('Webhook response keys:', webhookResponse.data ? Object.keys(webhookResponse.data) : 'none');
      webhookSent = true;
      webhookStatus = webhookResponse.status;
      
      // Verificar si el webhook respondió con "Failed."
      const webhookResponseText = typeof webhookResponse.data === 'string' 
        ? webhookResponse.data 
        : webhookResponse.data?.message || webhookResponse.data?.status || '';
      
      if (webhookResponseText === 'Failed.' || webhookResponseText.toLowerCase().includes('failed')) {
        console.log('⚠️ Webhook returned "Failed." - Refunding credit');
        
        // Primero obtener créditos actuales
        const { data: currentUser } = await supabase
          .from('users')
          .select('credits')
          .eq('id', req.userId)
          .single();
        
        // Reembolsar el crédito al usuario
        const { data: refundData, error: refundError } = await supabase
          .from('users')
          .update({ 
            credits: (currentUser?.credits || 0) + 1
          })
          .eq('id', req.userId)
          .select('credits')
          .single();
        
        if (refundError) {
          console.error('Error refunding credit:', refundError);
        } else {
          console.log('✅ Credit refunded. New balance:', refundData.credits);
        }
        
        // Actualizar submission como fallo
        if (submissionId) {
          await supabase.from('form_submissions')
            .update({
              success: false,
              error_message: 'La generación de la imagen falló en el servidor de IA',
              webhook_sent: true,
              webhook_response_status: webhookResponse.status,
              completed_at: new Date().toISOString()
            })
            .eq('id', submissionId);
        }
        
        return; // No podemos enviar respuesta, ya se envió
      }
      
      // Verificar si el webhook devolvió una URL de imagen
      // El webhook puede devolver:
      // 1. String directo con la URL
      // 2. Objeto con propiedades: {image_url: "...", url: "...", imageUrl: "..."}
      let imageUrl = null;
      if (typeof webhookResponse.data === 'string') {
        imageUrl = webhookResponse.data;
      } else if (typeof webhookResponse.data === 'object') {
        imageUrl = webhookResponse.data?.image_url || webhookResponse.data?.url || webhookResponse.data?.imageUrl;
      }
      
      console.log('🔍 Detected image URL:', imageUrl);
      console.log('🔍 Full response data:', JSON.stringify(webhookResponse.data, null, 2));
      
      if (imageUrl) {
        console.log('✅ Generated image URL received:', imageUrl);
        
        try {
          // Descargar la imagen generada
          const imageResponse = await axios.get(imageUrl, {
            responseType: 'arraybuffer',
            timeout: 30000
          });
          
          const imageBuffer = Buffer.from(imageResponse.data);
          
          // Optimizar imagen antes de guardar para reducir tamaño
          let optimizedBuffer;
          try {
            optimizedBuffer = await sharp(imageBuffer)
              .resize(1200, null, { // Máximo 1200px de ancho, mantener aspect ratio
                withoutEnlargement: true,
                fit: 'inside'
              })
              .jpeg({ quality: 85 }) // Convertir a JPEG con calidad 85%
              .toBuffer();
            
            const originalSize = (imageBuffer.length / 1024 / 1024).toFixed(2);
            const optimizedSize = (optimizedBuffer.length / 1024 / 1024).toFixed(2);
            const reduction = ((1 - optimizedBuffer.length / imageBuffer.length) * 100).toFixed(1);
            console.log(`📸 Imagen IA optimizada:`);
            console.log(`   Original: ${originalSize} MB`);
            console.log(`   Optimizada: ${optimizedSize} MB`);
            console.log(`   Reducción: ${reduction}%`);
          } catch (optimizeError) {
            console.warn('⚠️ No se pudo optimizar imagen IA, usando original:', optimizeError.message);
            optimizedBuffer = imageBuffer;
          }
          
          // Generar nombre único para la imagen generada
          const timestamp = Date.now();
          const generatedFileName = `${form_type || 'form'}_${timestamp}.jpg`; // Cambiar a .jpg
          const generatedPath = `${req.userId}/${generatedFileName}`;
          
          // Subir la imagen optimizada al bucket "generated" (minúscula)
          const { data: uploadData, error: uploadError } = await supabase
            .storage
            .from('generated')
            .upload(generatedPath, optimizedBuffer, {
              contentType: 'image/jpeg', // Cambiar a JPEG
              cacheControl: '3600',
              upsert: false
            });
          
          if (uploadError) {
            console.error('Error uploading generated image:', uploadError);
          } else {
            console.log('Generated image uploaded successfully to "generated" bucket:', generatedPath);
            
            // Crear URL pública de la imagen generada
            const { data: publicUrlData } = await supabase
              .storage
              .from('generated')
              .getPublicUrl(generatedPath);
            
            generatedImageUrl = publicUrlData.publicUrl;
            
            // Registrar en la tabla uploads para mantener referencia
            const { data: aiUploadData, error: aiUploadError } = await supabase.from('uploads').insert({
              owner_id: req.userId,
              filename: generatedFileName,
              path: generatedPath,
              folder: 'AI Generated',
              custom_name: `${form_type || 'Imagen'} - Generada por IA`,
              bucket_name: 'generated',
              mimetype: 'image/jpeg',
              size: optimizedBuffer.length
            }).select('id').single();
            
            // Store the AI image ID for linking with submission
            if (!aiUploadError && aiUploadData) {
              aiImageId = aiUploadData.id;
            }
          }
        } catch (downloadError) {
          console.error('Error downloading/uploading generated image:', downloadError.message);
        }
      }
      
      // Actualizar submission como exitoso
      if (submissionId) {
        await supabase.from('form_submissions')
          .update({
            ai_image_id: aiImageId || null,
            success: true,
            webhook_sent: true,
            webhook_response_status: webhookResponse.status,
            response_data: generatedImageUrl || imageUrl || null,
            completed_at: new Date().toISOString()
          })
          .eq('id', submissionId);
      }
      
      console.log('✅ Webhook processing completed successfully');
    } catch (webhookErr) {
      console.error('Webhook error:', webhookErr.message);
      errorMessage = webhookErr.message;
      
      // Actualizar submission como fallido
      if (submissionId) {
        await supabase.from('form_submissions')
          .update({
            success: false,
            error_message: `Webhook failed: ${webhookErr.message}`,
            webhook_sent: false,
            completed_at: new Date().toISOString()
          })
          .eq('id', submissionId);
      }
      
      console.log('❌ Webhook processing failed');
    }
    })(); // Fin del procesamiento asíncrono en background
  } catch (err) {
    console.error('submit-form error', err.message || err);
    
    // Save failed submission to database
    try {
      // Use the extracted photo_id variable, not req.body.photo_id
      const failedPhotoId = photo_id || req.body?.user_photo?.id || req.body?.photo_id || null;
      
      await supabase.from('form_submissions').insert([{
        user_id: req.userId,
        photo_id: failedPhotoId,
        form_type: req.body.form_type || null,
        product_id: req.body.product_id || null,
        market_sector: req.body.market_sector || null,
        product_description: req.body.product_description || null,
        logo_display_preference: req.body.logo_display_preference || null,
        success: false,
        error_message: err.message || String(err),
        webhook_sent: false,
        form_data: req.body || {},
        completed_at: new Date().toISOString()
      }]);
    } catch (dbErr) {
      console.error('Failed to save error submission:', dbErr.message);
    }
    
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get all form submissions for authenticated user
app.get('/api/form-submissions', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('form_submissions')
      .select(`
        *,
        user_photo:uploads!photo_id(filename, custom_name, folder),
        products(name, category)
      `)
      .eq('user_id', req.userId)
      .order('created_at', { ascending: false });
    
    if (error) throw error;

    // Add photo filename and product info to each submission
    const submissionsWithPhotos = await Promise.all(data.map(async (sub) => {
      let generatedImageUrl = null;
      
      // Primero intentar con ai_image_id (nuevo método - más preciso)
      if (sub.ai_image_id) {
        const { data: aiImage } = await supabase
          .from('uploads')
          .select('path, bucket_name')
          .eq('id', sub.ai_image_id)
          .eq('bucket_name', 'generated')
          .maybeSingle();
        
        if (aiImage) {
          const { data: urlData } = await supabase.storage
            .from('generated')
            .createSignedUrl(aiImage.path, 24 * 60 * 60);
          
          generatedImageUrl = urlData?.signedUrl || null;
        }
      } 
      // Fallback a métodos antiguos para envíos legacy
      else if (sub.response_data) {
        // Si response_data ya es una URL, usarla
        if (typeof sub.response_data === 'string' && sub.response_data.startsWith('http')) {
          generatedImageUrl = sub.response_data;
        } else {
          // Buscar imagen generada cerca de la fecha del submission (legacy)
          const submissionTime = new Date(sub.created_at);
          const timeWindowStart = new Date(submissionTime.getTime() - 60000); // 1 minuto antes
          const timeWindowEnd = new Date(submissionTime.getTime() + 120000); // 2 minutos después
          
          const { data: generatedImage } = await supabase
            .from('uploads')
            .select('*')
            .eq('owner_id', req.userId)
            .eq('folder', 'AI Generated')
            .gte('created_at', timeWindowStart.toISOString())
            .lte('created_at', timeWindowEnd.toISOString())
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();
          
          if (generatedImage) {
            // Generar URL firmada del bucket correcto
            const bucketName = generatedImage.bucket_name || 'generated';
            const { data: urlData } = await supabase.storage
              .from(bucketName)
              .createSignedUrl(generatedImage.path, 24 * 60 * 60);
            
            generatedImageUrl = urlData?.signedUrl || null;
          }
        }
      }
      
      return {
        ...sub,
        photo_filename: sub.user_photo?.custom_name || sub.user_photo?.filename || 'Foto eliminada',
        product_name: sub.products?.name || null,
        product_category: sub.products?.category || null,
        generated_image_url: generatedImageUrl
      };
    }));

    res.json({ ok: true, submissions: submissionsWithPhotos });
  } catch (err) {
    console.error('list form-submissions error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get single form submission details
app.get('/api/form-submissions/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const { data, error } = await supabase
      .from('form_submissions')
      .select(`
        *,
        user_photo:uploads!photo_id(filename, custom_name, folder),
        products(name, category)
      `)
      .eq('id', id)
      .eq('user_id', req.userId)
      .maybeSingle();
    
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Submission not found' });

    // Add photo filename and product info
    const submission = {
      ...data,
      photo_filename: data.user_photo?.custom_name || data.user_photo?.filename || 'Foto eliminada',
      product_name: data.products?.name || null,
      product_category: data.products?.category || null
    };

    res.json({ ok: true, submission });
  } catch (err) {
    console.error('get form-submission error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get products by form type
app.get('/api/products/:formType', authenticate, async (req, res) => {
  try {
    const { formType } = req.params;
    
    // Validate form type
    const validFormTypes = ['termoformado', 'doypack', 'flowpack'];
    if (!validFormTypes.includes(formType)) {
      return res.status(400).json({ ok: false, error: 'Tipo de formulario inválido' });
    }

    // Get products from database
    const { data: products, error } = await supabase
      .from('products')
      .select('*')
      .eq('form_type', formType)
      .eq('active', true)
      .order('category')
      .order('display_order');

    if (error) throw error;

    // Generate signed URLs for each product image
    const productsWithUrls = await Promise.all(
      products.map(async (product) => {
        try {
          // Generate signed URL valid for 24 hours
          const { data: urlData, error: urlError } = await supabase.storage
            .from('products')
            .createSignedUrl(product.image_path, 24 * 60 * 60);

          if (urlError) {
            console.error(`Error generating URL for ${product.image_path}:`, urlError);
            return {
              ...product,
              imageUrl: null,
              imageError: true
            };
          }

          return {
            ...product,
            imageUrl: urlData?.signedUrl || null
          };
        } catch (err) {
          console.error(`Exception for product ${product.id}:`, err);
          return {
            ...product,
            imageUrl: null,
            imageError: true
          };
        }
      })
    );

    // Group products by category
    const groupedProducts = productsWithUrls.reduce((acc, product) => {
      if (!acc[product.category]) {
        acc[product.category] = [];
      }
      acc[product.category].push(product);
      return acc;
    }, {});

    res.json({
      ok: true,
      products: productsWithUrls,
      groupedProducts
    });
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// =============== ADMIN ENDPOINTS ===============

// Check if current user is admin
app.get('/api/admin/check', authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('is_admin')
      .eq('id', req.userId)
      .single();
    
    if (error) throw error;
    
    res.json({ ok: true, is_admin: user?.is_admin || false });
  } catch (err) {
    console.error('Admin check error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Export user data (GDPR Data Portability)
app.get('/api/export-user-data/:userId?', authenticate, async (req, res) => {
  try {
    const PDFDocument = require('pdfkit');
    const archiver = require('archiver');
    const fs = require('fs');
    const path = require('path');
    
    console.log('Export user data request received');
    console.log('Params:', req.params);
    console.log('UserId from token:', req.userId);
    
    // Determine which user's data to export
    let targetUserId = req.params.userId;
    
    // If userId is provided in URL, check if requester is admin
    if (targetUserId && targetUserId !== req.userId) {
      const { data: requester } = await supabase
        .from('users')
        .select('is_admin, is_super_admin')
        .eq('id', req.userId)
        .single();
      
      if (!requester || !requester.is_admin) {
        return res.status(403).json({ error: 'Only admins can export other users data' });
      }

      // Check if target user is super admin
      const { data: targetUser } = await supabase
        .from('users')
        .select('is_super_admin')
        .eq('id', targetUserId)
        .single();

      // Only super admin can export another super admin's data
      if (targetUser?.is_super_admin && !requester.is_super_admin) {
        return res.status(403).json({ error: 'Solo el super administrador puede exportar los datos de otro super administrador' });
      }
    } else {
      // If no userId provided, export requester's own data
      targetUserId = req.userId;
    }

    // Fetch user data
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', targetUserId)
      .single();
    
    if (userError) throw userError;
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Fetch all uploads
    const { data: uploads, error: uploadsError } = await supabase
      .from('uploads')
      .select('*')
      .eq('owner_id', targetUserId)
      .order('created_at', { ascending: false });
    
    if (uploadsError) throw uploadsError;

    // Fetch all form submissions
    const { data: submissions, error: submissionsError } = await supabase
      .from('form_submissions')
      .select('*')
      .eq('user_id', targetUserId)
      .order('created_at', { ascending: false });
    
    if (submissionsError) throw submissionsError;

    console.log(`Found ${uploads?.length || 0} uploads`);
    console.log(`Found ${submissions?.length || 0} form submissions`);

    // Prepare JSON data
    const exportData = {
      export_date: new Date().toISOString(),
      user_information: {
        id: user.id,
        name: user.name,
        email: user.email,
        credits: user.credits,
        is_admin: user.is_admin,
        created_at: user.created_at
      },
      statistics: {
        total_uploads: uploads?.length || 0,
        ai_generated_images: uploads?.filter(u => u.folder === 'AI Generated').length || 0,
        regular_images: uploads?.filter(u => u.folder !== 'AI Generated').length || 0,
        total_submissions: submissions?.length || 0,
        total_storage_bytes: uploads?.reduce((sum, u) => sum + (u.file_size || 0), 0) || 0
      },
      uploads: uploads || [],
      form_submissions: submissions || []
    };

    // Create temporary directory for export
    const tempExportsDir = path.join(__dirname, 'temp_exports');
    if (!fs.existsSync(tempExportsDir)) {
      console.log('Creating temp_exports directory');
      fs.mkdirSync(tempExportsDir, { recursive: true });
    }
    
    const tempDir = path.join(tempExportsDir, targetUserId);
    if (!fs.existsSync(tempDir)) {
      console.log('Creating user temp directory:', tempDir);
      fs.mkdirSync(tempDir, { recursive: true });
    }

    // Generate PDF
    const pdfPath = path.join(tempDir, 'user_data_report.pdf');
    console.log('Generating PDF at:', pdfPath);
    const doc = new PDFDocument({ margin: 50 });
    const pdfStream = fs.createWriteStream(pdfPath);
    doc.pipe(pdfStream);

    // Helper function to convert UTC to Colombia time (UTC-5)
    function toColombiaTime(date) {
      const utcDate = new Date(date);
      const colombiaTime = new Date(utcDate.getTime() - (5 * 60 * 60 * 1000));
      return colombiaTime.toLocaleString('es-CO', { timeZone: 'UTC' });
    }

    // PDF Header
    doc.fontSize(24).font('Helvetica-Bold').text('Exportación de Datos Personales', { align: 'center' });
    doc.moveDown();
    doc.fontSize(10).font('Helvetica').text(`Generado el: ${toColombiaTime(new Date())}`, { align: 'center' });
    doc.text(`Conforme a la Ley 1581 de 2012 - Habeas Data`, { align: 'center' });
    doc.moveDown(2);

    // User Information Section
    doc.fontSize(16).font('Helvetica-Bold').text('Información del Usuario');
    doc.moveDown(0.5);
    doc.fontSize(11).font('Helvetica');
    doc.text(`Nombre: ${user.name}`);
    doc.text(`Email: ${user.email}`);
    doc.text(`ID de Usuario: ${user.id}`);
    doc.text(`Créditos Disponibles: ${user.credits}`);
    doc.text(`Tipo de cuenta: ${user.is_admin ? 'Administrador' : 'Usuario'}`);
    doc.text(`Fecha de Registro: ${toColombiaTime(user.created_at)}`);
    doc.moveDown(2);

    // Statistics Section
    doc.fontSize(16).font('Helvetica-Bold').text('Estadísticas');
    doc.moveDown(0.5);
    doc.fontSize(11).font('Helvetica');
    doc.text(`Total de imágenes subidas: ${exportData.statistics.total_uploads}`);
    doc.text(`   • Imágenes regulares: ${exportData.statistics.regular_images}`);
    doc.text(`   • Imágenes generadas por IA: ${exportData.statistics.ai_generated_images}`);
    doc.text(`Total de formularios enviados: ${exportData.statistics.total_submissions}`);
    doc.text(`Almacenamiento total: ${(exportData.statistics.total_storage_bytes / (1024 * 1024)).toFixed(2)} MB`);
    doc.moveDown(2);

    // Uploads Section
    const regularImages = uploads?.filter(u => u.folder !== 'AI Generated') || [];
    const aiImages = uploads?.filter(u => u.folder === 'AI Generated') || [];
    
    if (regularImages.length > 0) {
      doc.addPage();
      doc.fontSize(16).font('Helvetica-Bold').text('Imágenes Regulares Subidas');
      doc.moveDown(1);
      
      regularImages.forEach((upload, index) => {
        if (index > 0 && index % 8 === 0) {
          doc.addPage();
        }
        
        doc.fontSize(11).font('Helvetica-Bold').text(`${index + 1}. ${upload.filename || 'Sin nombre'}`);
        doc.fontSize(9).font('Helvetica');
        doc.text(`   ID: ${upload.id}`);
        doc.text(`   Carpeta: ${upload.folder || 'Sin carpeta'}`);
        doc.text(`   Nombre personalizado: ${upload.custom_name || 'N/A'}`);
        doc.text(`   Tipo: ${upload.file_type || 'N/A'}`);
        doc.text(`   Tamaño: ${((upload.file_size || 0) / 1024).toFixed(2)} KB`);
        doc.text(`   Fecha: ${toColombiaTime(upload.created_at)}`);
        doc.moveDown(0.5);
      });
    }

    // AI Generated Images Section
    if (aiImages.length > 0) {
      doc.addPage();
      doc.fontSize(16).font('Helvetica-Bold').text('Imágenes Generadas por IA');
      doc.moveDown(1);
      
      aiImages.forEach((upload, index) => {
        if (index > 0 && index % 8 === 0) {
          doc.addPage();
        }
        
        doc.fontSize(11).font('Helvetica-Bold').text(`${index + 1}. ${upload.filename || 'Sin nombre'}`);
        doc.fontSize(9).font('Helvetica');
        doc.text(`   ID: ${upload.id}`);
        doc.text(`   Nombre: ${upload.custom_name || 'N/A'}`);
        doc.text(`   Fecha de generación: ${toColombiaTime(upload.created_at)}`);
        doc.text(`   Bucket: ${upload.bucket_name || 'generated'}`);
        doc.moveDown(0.5);
      });
    }

    // Form Submissions Section
    if (submissions && submissions.length > 0) {
      doc.addPage();
      doc.fontSize(16).font('Helvetica-Bold').text('Formularios Enviados');
      doc.moveDown(1);
      
      submissions.forEach((submission, index) => {
        if (index > 0 && index % 5 === 0) {
          doc.addPage();
        }
        
        doc.fontSize(11).font('Helvetica-Bold').text(`${index + 1}. Formulario: ${submission.form_type || 'N/A'}`);
        doc.fontSize(9).font('Helvetica');
        doc.text(`   ID: ${submission.id}`);
        doc.text(`   Fecha: ${toColombiaTime(submission.created_at)}`);
        
        // Parse and display form data
        if (submission.form_data) {
          try {
            const formData = typeof submission.form_data === 'string' 
              ? JSON.parse(submission.form_data) 
              : submission.form_data;
            
            console.log(`Submission ${index + 1} form_data:`, formData);
            
            doc.text(`   Datos del formulario:`);
            Object.entries(formData).forEach(([key, value]) => {
              if (key !== 'photos' && typeof value !== 'object') {
                doc.text(`     • ${key}: ${value}`);
              }
            });
          } catch (e) {
            console.error(`Error parsing form_data for submission ${index + 1}:`, e);
            doc.text(`   Datos: ${submission.form_data}`);
          }
        } else {
          console.log(`Submission ${index + 1} has no form_data`);
        }
        
        if (submission.response_data) {
          doc.text(`   Respuesta IA: ${submission.response_data.substring(0, 100)}...`);
        }
        
        doc.moveDown(0.5);
      });
    }

    // Footer
    doc.addPage();
    doc.fontSize(10).font('Helvetica').text('Este documento contiene todos los datos personales almacenados en nuestra plataforma.', { align: 'center' });
    doc.text('Conforme al derecho de portabilidad establecido en la Ley 1581 de 2012.', { align: 'center' });
    doc.moveDown();
    doc.text('ALICO S.A.', { align: 'center' });
    doc.text('Calle 10 Sur N° 50FF 127 - Guayabal, Medellín, Colombia', { align: 'center' });
    doc.text('(604) 360 00 30', { align: 'center' });

    doc.end();

    // Wait for PDF to finish
    await new Promise((resolve, reject) => {
      pdfStream.on('finish', resolve);
      pdfStream.on('error', reject);
    });

    // Save JSON data
    const jsonPath = path.join(tempDir, 'user_data.json');
    fs.writeFileSync(jsonPath, JSON.stringify(exportData, null, 2));

    // Download images from Supabase Storage
    const imagesDir = path.join(tempDir, 'images');
    const aiImagesDir = path.join(tempDir, 'ai_generated_images');
    if (!fs.existsSync(imagesDir)) {
      fs.mkdirSync(imagesDir, { recursive: true });
    }
    if (!fs.existsSync(aiImagesDir)) {
      fs.mkdirSync(aiImagesDir, { recursive: true });
    }

    let regularImagesCount = 0;
    let aiImagesCount = 0;

    if (uploads && uploads.length > 0) {
      console.log(`Found ${uploads.length} uploads to download`);
      for (const upload of uploads) {
        if (upload.path) {
          try {
            // Determinar si es imagen generada por IA para usar el bucket correcto
            const isAIGenerated = upload.folder === 'AI Generated';
            const bucketName = isAIGenerated ? 'generated' : 'uploads';
            
            console.log(`Downloading image from bucket "${bucketName}": ${upload.path}`);
            const { data: imageData, error: downloadError } = await supabase
              .storage
              .from(bucketName)
              .download(upload.path);
            
            if (downloadError) {
              console.error(`Error downloading ${upload.path} from ${bucketName}:`, downloadError);
            } else if (imageData) {
              const buffer = Buffer.from(await imageData.arrayBuffer());
              
              // Determine if it's an AI generated image
              const isAIGenerated = upload.folder === 'AI Generated';
              const targetDir = isAIGenerated ? aiImagesDir : imagesDir;
              const imagePath = path.join(targetDir, upload.filename || `image_${upload.id}.jpg`);
              
              fs.writeFileSync(imagePath, buffer);
              console.log(`Image saved: ${upload.filename} (${isAIGenerated ? 'AI Generated' : 'Regular'})`);
              
              if (isAIGenerated) {
                aiImagesCount++;
              } else {
                regularImagesCount++;
              }
            }
          } catch (err) {
            console.error(`Error downloading image ${upload.id}:`, err);
          }
        }
      }
    } else {
      console.log('No uploads found for this user');
    }

    // Create README
    const readmePath = path.join(tempDir, 'README.txt');
    
    // Helper function for Colombia time in README (reuse from PDF)
    const getColombiaNow = () => {
      const utcDate = new Date();
      const colombiaTime = new Date(utcDate.getTime() - (5 * 60 * 60 * 1000));
      return colombiaTime.toLocaleString('es-CO', { timeZone: 'UTC' });
    };
    
    const readmeContent = `EXPORTACIÓN DE DATOS PERSONALES
================================

Generado el: ${getColombiaNow()}
Usuario: ${user.name} (${user.email})

CONTENIDO DE ESTE ARCHIVO:
--------------------------

1. user_data_report.pdf
   Informe completo en formato PDF con toda la información del usuario,
   estadísticas y detalles de formularios enviados.

2. user_data.json
   Archivo JSON con todos los datos estructurados y legibles por máquina.
   Incluye información del usuario, uploads y formularios enviados.

3. images/ (carpeta)
   Contiene todas las imágenes originales subidas por el usuario.
   Total de imágenes regulares: ${regularImagesCount}

4. ai_generated_images/ (carpeta)
   Contiene todas las imágenes generadas por Inteligencia Artificial.
   Total de imágenes generadas por IA: ${aiImagesCount}

RESUMEN:
--------
Total de imágenes: ${uploads?.length || 0}
Almacenamiento total: ${(exportData.statistics.total_storage_bytes / (1024 * 1024)).toFixed(2)} MB

DERECHOS DEL TITULAR:
--------------------

Esta exportación se realiza conforme al derecho de portabilidad establecido
en la Ley 1581 de 2012 de Protección de Datos Personales en Colombia.

Usted tiene derecho a:
- Conocer, actualizar y rectificar sus datos personales
- Solicitar la supresión de sus datos
- Revocar la autorización otorgada
- Presentar quejas ante la Superintendencia de Industria y Comercio

Para ejercer estos derechos, contacte a:
Email: servicioalcliente@alico-sa.com
Teléfono: (604) 360 00 30

ALICO S.A.
Calle 10 Sur N° 50FF 127 - Guayabal
Medellín, Antioquia, Colombia
`;
    fs.writeFileSync(readmePath, readmeContent);

    // Create ZIP archive
    const zipPath = path.join(__dirname, 'temp_exports', `user_data_${targetUserId}_${Date.now()}.zip`);
    console.log('Creating ZIP at:', zipPath);
    const output = fs.createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    archive.pipe(output);
    archive.directory(tempDir, false);
    await archive.finalize();

    // Wait for ZIP to finish
    await new Promise((resolve, reject) => {
      output.on('close', resolve);
      output.on('error', reject);
    });

    console.log('ZIP created successfully, sending to client');
    
    // Send ZIP file
    res.download(zipPath, `datos_personales_${user.name.replace(/\s/g, '_')}_${new Date().toISOString().split('T')[0]}.zip`, (err) => {
      // Cleanup temporary files
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
        fs.unlinkSync(zipPath);
      } catch (cleanupErr) {
        console.error('Error cleaning up temp files:', cleanupErr);
      }

      if (err) {
        console.error('Error sending file:', err);
      }
    });

  } catch (err) {
    console.error('export-user-data error', err.message || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get admin dashboard statistics
app.get('/api/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
  try {
    // Total users
    const { count: totalUsers, error: usersError } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });
    
    if (usersError) throw usersError;

    // Total uploads
    const { count: totalUploads, error: uploadsError } = await supabase
      .from('uploads')
      .select('*', { count: 'exact', head: true });
    
    if (uploadsError) throw uploadsError;

    // AI Generated images (folder = "AI Generated")
    const { count: aiGeneratedImages, error: aiError } = await supabase
      .from('uploads')
      .select('*', { count: 'exact', head: true })
      .eq('folder', 'AI Generated');
    
    if (aiError) throw aiError;

    // Total form submissions
    const { count: totalSubmissions, error: submissionsError } = await supabase
      .from('form_submissions')
      .select('*', { count: 'exact', head: true });
    
    if (submissionsError) throw submissionsError;

    // Successful submissions
    const { count: successfulSubmissions, error: successError } = await supabase
      .from('form_submissions')
      .select('*', { count: 'exact', head: true })
      .eq('success', true);
    
    if (successError) throw successError;

    // Submissions by form type
    const { data: submissionsByType, error: typeError } = await supabase
      .from('form_submissions')
      .select('form_type');
    
    if (typeError) throw typeError;

    const formTypeStats = submissionsByType.reduce((acc, sub) => {
      const type = sub.form_type || 'sin_tipo';
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});

    // Recent submissions (last 7)
    const { data: recentSubmissions, error: recentError } = await supabase
      .from('form_submissions')
      .select(`
        id,
        created_at,
        form_type,
        success,
        users(name, email)
      `)
      .order('created_at', { ascending: false })
      .limit(7);
    
    if (recentError) throw recentError;

    // Total credits distributed
    const { data: usersCredits, error: creditsError } = await supabase
      .from('users')
      .select('credits');
    
    if (creditsError) throw creditsError;

    const totalCredits = usersCredits.reduce((sum, user) => sum + (user.credits || 0), 0);

    // Storage usage (approximate from uploads table)
    const { data: uploadsSize, error: sizeError } = await supabase
      .from('uploads')
      .select('size');
    
    if (sizeError) throw sizeError;

    const totalStorageBytes = uploadsSize.reduce((sum, upload) => sum + (upload.size || 0), 0);
    const totalStorageMB = (totalStorageBytes / (1024 * 1024)).toFixed(2);

    res.json({
      ok: true,
      stats: {
        totalUsers,
        totalUploads,
        aiGeneratedImages,
        totalSubmissions,
        successfulSubmissions,
        failedSubmissions: totalSubmissions - successfulSubmissions,
        formTypeStats,
        totalCredits,
        totalStorageMB,
        recentSubmissions: recentSubmissions.map(sub => ({
          id: sub.id,
          created_at: sub.created_at,
          form_type: sub.form_type,
          success: sub.success,
          user_name: sub.users?.name || 'Desconocido',
          user_email: sub.users?.email || 'N/A'
        }))
      }
    });
  } catch (err) {
    console.error('Dashboard stats error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, name, email, created_at, credits, credits_last_reset, is_admin, is_super_admin, banned, banned_at, banned_reason, banned_by')
      .order('created_at', { ascending: false });
    
    if (error) throw error;

    // Get upload stats for each user (including AI-generated images)
    const usersWithStats = await Promise.all(users.map(async (user) => {
      const { data: uploads, error: uploadsError } = await supabase
        .from('uploads')
        .select('size, bucket_name')
        .eq('owner_id', user.id);
      
      let totalPhotos = 0;
      let totalSize = 0;
      let userPhotos = 0;
      let userPhotosSize = 0;
      let aiPhotos = 0;
      let aiPhotosSize = 0;
      
      if (!uploadsError && uploads) {
        totalPhotos = uploads.length;
        totalSize = uploads.reduce((sum, upload) => sum + (upload.size || 0), 0);
        
        // Separate user uploads from AI-generated images
        uploads.forEach(upload => {
          const size = upload.size || 0;
          if (upload.bucket_name === 'generated') {
            aiPhotos++;
            aiPhotosSize += size;
          } else {
            userPhotos++;
            userPhotosSize += size;
          }
        });
      }

      // Get banned_by user name if applicable
      let banned_by_name = null;
      if (user.banned_by) {
        const { data: bannedByUser } = await supabase
          .from('users')
          .select('name, email')
          .eq('id', user.banned_by)
          .single();
        
        if (bannedByUser) {
          banned_by_name = bannedByUser.name || bannedByUser.email;
        }
      }
      
      return {
        ...user,
        total_photos: totalPhotos,
        total_size_bytes: totalSize,
        total_size_mb: (totalSize / (1024 * 1024)).toFixed(2),
        user_photos: userPhotos,
        user_photos_size_mb: (userPhotosSize / (1024 * 1024)).toFixed(2),
        ai_photos: aiPhotos,
        ai_photos_size_mb: (aiPhotosSize / (1024 * 1024)).toFixed(2),
        banned_by_name
      };
    }));

    res.json({ ok: true, users: usersWithStats });
  } catch (err) {
    console.error('Get all users error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Get all form submissions (admin only)
app.get('/api/admin/submissions', authenticateAdmin, async (req, res) => {
  try {
    const { data: submissions, error } = await supabase
      .from('form_submissions')
      .select(`
        *,
        users(name, email),
        user_photo:uploads!photo_id(filename, custom_name),
        products(name, category)
      `)
      .order('created_at', { ascending: false });
    
    if (error) throw error;

    // Enrich submissions with AI image data
    const submissionsWithInfo = await Promise.all(submissions.map(async (sub) => {
      // Find AI-generated image using ai_image_id if available
      let aiImageUrl = null;
      
      if (sub.ai_image_id) {
        // Direct lookup using ai_image_id (new method - more accurate)
        const { data: aiImage, error: aiError } = await supabase
          .from('uploads')
          .select('path, bucket_name')
          .eq('id', sub.ai_image_id)
          .eq('bucket_name', 'generated')
          .single();
        
        if (!aiError && aiImage) {
          const { data: publicUrl } = supabase.storage
            .from('generated')
            .getPublicUrl(aiImage.path);
          
          aiImageUrl = publicUrl?.publicUrl || null;
        }
      } else if (sub.user_id && sub.created_at) {
        // Fallback to time-based lookup for old submissions (legacy method)
        const { data: aiImages, error: aiError } = await supabase
          .from('uploads')
          .select('path, bucket_name')
          .eq('owner_id', sub.user_id)
          .eq('bucket_name', 'generated')
          .gte('created_at', new Date(new Date(sub.created_at).getTime() - 60000).toISOString()) // 1 min before
          .lte('created_at', new Date(new Date(sub.created_at).getTime() + 120000).toISOString()) // 2 min after
          .order('created_at', { ascending: false })
          .limit(1);
        
        if (!aiError && aiImages && aiImages.length > 0) {
          const aiImage = aiImages[0];
          const { data: publicUrl } = supabase.storage
            .from('generated')
            .getPublicUrl(aiImage.path);
          
          aiImageUrl = publicUrl?.publicUrl || null;
        }
      }

      return {
        ...sub,
        user_name: sub.users?.name || 'Desconocido',
        user_email: sub.users?.email || 'N/A',
        photo_filename: sub.user_photo?.custom_name || sub.user_photo?.filename || 'Foto eliminada',
        product_name: sub.products?.name || null,
        product_category: sub.products?.category || null,
        ai_image_url: aiImageUrl
      };
    }));

    res.json({ ok: true, submissions: submissionsWithInfo });
  } catch (err) {
    console.error('Get all submissions error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Update user admin status (admin only)
app.patch('/api/admin/users/:id/admin-status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_admin } = req.body;

    if (typeof is_admin !== 'boolean') {
      return res.status(400).json({ error: 'is_admin must be a boolean' });
    }

    // Check if target user is super admin
    const { data: targetUser } = await supabase
      .from('users')
      .select('is_super_admin, is_admin')
      .eq('id', id)
      .single();

    // Prevent modification of super admin status
    if (targetUser?.is_super_admin) {
      return res.status(403).json({ error: 'No se puede modificar el estado de super administrador' });
    }

    // Prevent users from removing their own admin status
    if (id === req.userId && !is_admin) {
      return res.status(400).json({ error: 'No puedes remover tu propio acceso de administrador' });
    }

    const { data, error } = await supabase
      .from('users')
      .update({ is_admin })
      .eq('id', id)
      .select('id, name, email, is_admin')
      .single();
    
    if (error) throw error;

    res.json({ ok: true, user: data });
  } catch (err) {
    console.error('Update admin status error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Update user credits (admin only)
app.patch('/api/admin/users/:id/credits', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { credits } = req.body;

    if (typeof credits !== 'number' || credits < 0) {
      return res.status(400).json({ error: 'credits must be a non-negative number' });
    }

    // Check if target user is super admin
    const { data: targetUser } = await supabase
      .from('users')
      .select('is_super_admin')
      .eq('id', id)
      .single();

    // Cannot modify super admin credits
    if (targetUser?.is_super_admin) {
      return res.status(403).json({ error: 'No se pueden modificar los créditos del super administrador' });
    }

    const { data, error } = await supabase
      .from('users')
      .update({ credits })
      .eq('id', id)
      .select('id, name, email, credits')
      .single();
    
    if (error) throw error;

    res.json({ ok: true, user: data });
  } catch (err) {
    console.error('Update credits error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Ban user (admin only)
app.post('/api/admin/users/:id/ban', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    // Prevent users from banning themselves
    if (id === req.userId) {
      return res.status(400).json({ error: 'No puedes banearte a ti mismo' });
    }

    // Check if user exists and get their admin status
    const { data: targetUser, error: fetchError } = await supabase
      .from('users')
      .select('id, name, email, is_admin, is_super_admin')
      .eq('id', id)
      .single();

    if (fetchError) throw fetchError;
    if (!targetUser) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Cannot ban super admin
    if (targetUser.is_super_admin) {
      return res.status(403).json({ error: 'No se puede banear al super administrador' });
    }

    // Prevent banning other admins (unless you're super admin)
    if (targetUser.is_admin && !req.isSuperAdmin) {
      return res.status(400).json({ error: 'Solo el super administrador puede banear a otros administradores' });
    }

    const { data, error } = await supabase
      .from('users')
      .update({ 
        banned: true,
        banned_at: new Date().toISOString(),
        banned_reason: reason || 'Violación de los términos de servicio',
        banned_by: req.userId
      })
      .eq('id', id)
      .select('id, name, email, banned, banned_at, banned_reason')
      .single();
    
    if (error) throw error;

    res.json({ ok: true, user: data, message: 'Usuario baneado exitosamente' });
  } catch (err) {
    console.error('Ban user error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Unban user (admin only)
app.post('/api/admin/users/:id/unban', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from('users')
      .update({ 
        banned: false,
        banned_at: null,
        banned_reason: null,
        banned_by: null
      })
      .eq('id', id)
      .select('id, name, email, banned')
      .single();
    
    if (error) throw error;

    res.json({ ok: true, user: data, message: 'Usuario desbaneado exitosamente' });
  } catch (err) {
    console.error('Unban user error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Delete user completely (admin only) - removes all associated data
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent admin from deleting themselves
    if (id === req.userId) {
      return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta mientras eres admin' });
    }

    // Check if target user is super admin or admin
    const { data: targetUser } = await supabase
      .from('users')
      .select('is_super_admin, is_admin, name')
      .eq('id', id)
      .single();

    // Super admin cannot be deleted by anyone
    if (targetUser?.is_super_admin) {
      return res.status(403).json({ error: 'No se puede eliminar al super administrador' });
    }

    // Only super admin can delete other admins
    if (targetUser?.is_admin && !req.isSuperAdmin) {
      return res.status(403).json({ error: 'Solo el super administrador puede eliminar a otros administradores' });
    }

    console.log(`🗑️ Starting complete deletion for user: ${id}`);

    // 1. Get all uploads to delete from storage
    const { data: uploads, error: uploadsError } = await supabase
      .from('uploads')
      .select('*')
      .eq('owner_id', id);
    
    if (uploadsError) throw uploadsError;

    console.log(`Found ${uploads?.length || 0} uploads to delete`);

    // 2. Delete files from storage buckets
    if (uploads && uploads.length > 0) {
      // Group by bucket
      const uploadsByBucket = uploads.reduce((acc, upload) => {
        const bucket = upload.bucket_name || 'uploads';
        if (!acc[bucket]) acc[bucket] = [];
        acc[bucket].push(upload);
        return acc;
      }, {});

      // Delete from each bucket
      for (const [bucketName, bucketUploads] of Object.entries(uploadsByBucket)) {
        const filesToDelete = [];
        bucketUploads.forEach(upload => {
          if (upload.path) filesToDelete.push(upload.path);
          if (upload.thumbnail_path) filesToDelete.push(upload.thumbnail_path);
        });

        if (filesToDelete.length > 0) {
          console.log(`Deleting ${filesToDelete.length} files from bucket "${bucketName}"`);
          const { error: storageError } = await supabase
            .storage
            .from(bucketName)
            .remove(filesToDelete);
          
          if (storageError) {
            console.warn(`Warning deleting from ${bucketName}:`, storageError.message);
          } else {
            console.log(`✅ Deleted ${filesToDelete.length} files from "${bucketName}"`);
          }
        }
      }
    }

    // 3. Delete from database tables (order matters due to foreign keys)
    
    // Delete form submissions
    const { error: submissionsError } = await supabase
      .from('form_submissions')
      .delete()
      .eq('user_id', id);
    
    if (submissionsError) {
      console.warn('Error deleting form_submissions:', submissionsError.message);
    } else {
      console.log('✅ Deleted form_submissions');
    }

    // Delete uploads records
    const { error: uploadsDeleteError } = await supabase
      .from('uploads')
      .delete()
      .eq('owner_id', id);
    
    if (uploadsDeleteError) {
      console.warn('Error deleting uploads:', uploadsDeleteError.message);
    } else {
      console.log('✅ Deleted uploads records');
    }

    // Delete mobile upload tokens
    const { error: tokensError } = await supabase
      .from('mobile_upload_tokens')
      .delete()
      .eq('user_id', id);
    
    if (tokensError) {
      console.warn('Error deleting mobile_upload_tokens:', tokensError.message);
    } else {
      console.log('✅ Deleted mobile_upload_tokens');
    }

    // 4. Finally, delete the user
    const { error: userError } = await supabase
      .from('users')
      .delete()
      .eq('id', id);
    
    if (userError) throw userError;

    console.log('✅ User deleted successfully');

    res.json({ 
      ok: true, 
      message: 'Usuario y todos sus datos eliminados exitosamente',
      deleted: {
        files: uploads?.length || 0,
        user_id: id
      }
    });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ error: err.message || String(err) });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
