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

const app = express();
const upload = multer({ dest: path.join(__dirname, 'uploads') });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Supabase client (use service role key on server only)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Validate environment variables
if (!supabaseUrl || !supabaseKey) {
  console.error('❌ Missing required environment variables!');
  console.error('SUPABASE_URL:', supabaseUrl ? '✓ Set' : '✗ Missing');
  console.error('SUPABASE_SERVICE_ROLE_KEY:', supabaseKey ? '✓ Set' : '✗ Missing');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

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
    next();
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
    
    // Check if user is admin
    const { data: user, error } = await supabase
      .from('users')
      .select('is_admin')
      .eq('id', req.userId)
      .single();
    
    if (error) throw error;
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    
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
  // Use specific password reset webhook if configured, otherwise fall back to general webhook
  return req.headers['x-webhook-url'] || process.env.PASSWORD_RESET_WEBHOOK_URL || process.env.WEBHOOK_URL;
}

async function postToWebhook(webhookUrl, payload, headers = {}) {
  if (!webhookUrl) throw new Error('No webhook URL configured');
  const res = await axios.post(webhookUrl, payload, { headers });
  return res.data;
}

// Login endpoint: validate credentials and return JWT
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
    if (error) throw error;
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin || false } });
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
    const password_hash = bcrypt.hashSync(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ name, email, password_hash }])
      .select('*')
      .single();

    if (error) {
      // unique violation handling
      if (error.code === '23505' || (error.message && error.message.toLowerCase().includes('duplicate'))) {
        return res.status(400).json({ error: 'email already exists' });
      }
      throw error;
    }

    const webhookUrl = getWebhookUrlFromReq(req);
    const payload = { action: 'register', data: { id: data.id, name: data.name, email: data.email, created_at: data.created_at } };
    if (webhookUrl) {
      try {
        await postToWebhook(webhookUrl, payload, { 'Content-Type': 'application/json' });
      } catch (err) {
        console.error('webhook error', err.message);
        // do not fail registration because webhook failed
      }
    }

    res.json({ ok: true, id: data.id });
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
    const { data: user, error: fetchErr } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!user) return res.status(404).json({ error: 'user not found' });

    const ok = bcrypt.compareSync(oldPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'old password incorrect' });

    const newHash = bcrypt.hashSync(newPassword, 10);
    const { data, error: upErr } = await supabase.from('users').update({ password_hash: newHash }).eq('id', user.id).select('*').single();
    if (upErr) throw upErr;

    const webhookUrl = getWebhookUrlFromReq(req);
    const payload = { action: 'change-password', data: { id: data.id, email: data.email, updated_at: data.updated_at || new Date().toISOString() } };
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

// Forgot password: generates reset token and sends to webhook
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email is required' });

  try {
    // Check if user exists
    const { data: user, error: fetchErr } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
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
    const { data: user } = await supabase.from('users').select('*').eq('id', resetToken.user_id).single();
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
      .select('id, name, email, credits, is_admin, created_at')
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
app.post('/api/upload', authenticate, upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'file is required' });

  try {
    // upload to Supabase storage
    const safeName = sanitizeFilename(file.originalname);
    const unique = uuidv4();
    const prefix = String(req.userId); // use authenticated userId
    const pathInBucket = `uploads/${prefix}/${unique}-${safeName}`;
    const thumbnailPath = `uploads/${prefix}/thumb-${unique}-${safeName}`;
    
    // Read and optimize original image
    const fileBuffer = fs.readFileSync(file.path);

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

// List user uploads (protected)
app.get('/api/uploads', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('uploads').select('*').eq('owner_id', req.userId).order('created_at', { ascending: false });
    if (error) throw error;

    // generate signed URLs for each upload (both original and thumbnail)
    const uploadsWithUrls = await Promise.all(data.map(async (upload) => {
      const { data: urlData } = await supabase.storage.from('uploads').createSignedUrl(upload.path, 24 * 60 * 60);
      let thumbnailUrl = null;
      
      // Get thumbnail URL if exists
      if (upload.thumbnail_path) {
        const { data: thumbData } = await supabase.storage.from('uploads').createSignedUrl(upload.thumbnail_path, 24 * 60 * 60);
        thumbnailUrl = thumbData?.signedUrl || null;
      }
      
      return { 
        ...upload, 
        signedUrl: urlData?.signedUrl || null,
        thumbnailUrl: thumbnailUrl 
      };
    }));

    res.json({ ok: true, uploads: uploadsWithUrls });
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

    // delete from storage (both original and thumbnail)
    const filesToDelete = [upload.path];
    if (upload.thumbnail_path) {
      filesToDelete.push(upload.thumbnail_path);
    }
    
    const { error: delErr } = await supabase.storage.from('uploads').remove(filesToDelete);
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
  const { photo_id, form_type, product_id, ...formData } = req.body || {};
  
  if (!photo_id) {
    return res.status(400).json({ error: 'photo_id is required' });
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
    if (product_id) {
      const { data: product, error: productErr } = await supabase
        .from('products')
        .select('id, name, category, image_path, description')
        .eq('id', product_id)
        .single();
      
      if (!productErr && product) {
        // Get public URL for product image (5 minutes validity)
        const { data: productUrlData } = await supabase.storage
          .from('products')
          .createSignedUrl(product.image_path, fiveMinutesInSeconds);
        
        productInfo = {
          id: product.id,
          name: product.name,
          category: product.category,
          description: product.description,
          image_url: productUrlData?.signedUrl || null
        };
      }
    }

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
      form_data: formData // Additional form fields
    };

    // Send to Alico webhook
    const webhookUrl = 'https://apps.alico-sa.com/webhook/ai-form';
    let webhookSent = false;
    let webhookStatus = null;
    let errorMessage = null;
    
    try {
      const webhookResponse = await axios.post(webhookUrl, webhookPayload, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000 // 10 seconds timeout
      });
      
      console.log('Webhook sent successfully:', webhookResponse.status);
      webhookSent = true;
      webhookStatus = webhookResponse.status;
      
      // Save successful submission to database
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now
      await supabase.from('form_submissions').insert([{
        user_id: req.userId,
        photo_id: photo_id,
        form_type: form_type || null,
        product_id: product_id || null,
        success: true,
        webhook_sent: true,
        webhook_url: webhookUrl,
        webhook_response_status: webhookResponse.status,
        temp_image_url: urlData.signedUrl,
        temp_url_expires_at: expiresAt.toISOString(),
        form_data: formData,
        completed_at: new Date().toISOString()
      }]);
      
      res.json({ 
        ok: true, 
        message: 'Form submitted successfully',
        webhook_sent: true,
        webhook_status: webhookResponse.status,
        public_url: urlData.signedUrl
      });
    } catch (webhookErr) {
      console.error('Webhook error:', webhookErr.message);
      errorMessage = webhookErr.message;
      
      // Save failed webhook submission to database
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
      await supabase.from('form_submissions').insert([{
        user_id: req.userId,
        photo_id: photo_id,
        form_type: form_type || null,
        product_id: product_id || null,
        success: true, // Form was processed successfully
        error_message: `Webhook failed: ${webhookErr.message}`,
        webhook_sent: false,
        webhook_url: webhookUrl,
        temp_image_url: urlData.signedUrl,
        temp_url_expires_at: expiresAt.toISOString(),
        form_data: formData,
        completed_at: new Date().toISOString()
      }]);
      
      // Still return success but indicate webhook failed
      res.json({ 
        ok: true, 
        message: 'Form submitted but webhook failed',
        webhook_sent: false,
        webhook_error: webhookErr.message,
        public_url: urlData.signedUrl
      });
    }
  } catch (err) {
    console.error('submit-form error', err.message || err);
    
    // Save failed submission to database
    try {
      await supabase.from('form_submissions').insert([{
        user_id: req.userId,
        photo_id: req.body.photo_id || null,
        form_type: req.body.form_type || null,
        product_id: req.body.product_id || null,
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
        uploads(filename, custom_name, folder),
        products(name, category)
      `)
      .eq('user_id', req.userId)
      .order('created_at', { ascending: false });
    
    if (error) throw error;

    // Add photo filename and product info to each submission
    const submissionsWithPhotos = data.map(sub => ({
      ...sub,
      photo_filename: sub.uploads?.custom_name || sub.uploads?.filename || 'Foto eliminada',
      product_name: sub.products?.name || null,
      product_category: sub.products?.category || null
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
        uploads(filename, custom_name, folder),
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
      photo_filename: data.uploads?.custom_name || data.uploads?.filename || 'Foto eliminada',
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
    
    // Determine which user's data to export
    let targetUserId = req.params.userId;
    
    // If userId is provided in URL, check if requester is admin
    if (targetUserId && targetUserId !== req.user.id) {
      const { data: requester } = await supabase
        .from('users')
        .select('is_admin')
        .eq('id', req.user.id)
        .single();
      
      if (!requester || !requester.is_admin) {
        return res.status(403).json({ error: 'Only admins can export other users data' });
      }
    } else {
      // If no userId provided, export requester's own data
      targetUserId = req.user.id;
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
      .eq('user_id', targetUserId)
      .order('created_at', { ascending: false });
    
    if (uploadsError) throw uploadsError;

    // Fetch all form submissions
    const { data: submissions, error: submissionsError } = await supabase
      .from('form_submissions')
      .select('*')
      .eq('user_id', targetUserId)
      .order('created_at', { ascending: false });
    
    if (submissionsError) throw submissionsError;

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
        total_submissions: submissions?.length || 0,
        total_storage_bytes: uploads?.reduce((sum, u) => sum + (u.file_size || 0), 0) || 0
      },
      uploads: uploads || [],
      form_submissions: submissions || []
    };

    // Create temporary directory for export
    const tempDir = path.join(__dirname, 'temp_exports', targetUserId);
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    // Generate PDF
    const pdfPath = path.join(tempDir, 'user_data_report.pdf');
    const doc = new PDFDocument({ margin: 50 });
    const pdfStream = fs.createWriteStream(pdfPath);
    doc.pipe(pdfStream);

    // PDF Header
    doc.fontSize(24).font('Helvetica-Bold').text('Exportación de Datos Personales', { align: 'center' });
    doc.moveDown();
    doc.fontSize(10).font('Helvetica').text(`Generado el: ${new Date().toLocaleString('es-CO')}`, { align: 'center' });
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
    doc.text(`Fecha de Registro: ${new Date(user.created_at).toLocaleString('es-CO')}`);
    doc.moveDown(2);

    // Statistics Section
    doc.fontSize(16).font('Helvetica-Bold').text('Estadísticas');
    doc.moveDown(0.5);
    doc.fontSize(11).font('Helvetica');
    doc.text(`Total de imágenes subidas: ${exportData.statistics.total_uploads}`);
    doc.text(`Total de formularios enviados: ${exportData.statistics.total_submissions}`);
    doc.text(`Almacenamiento total: ${(exportData.statistics.total_storage_bytes / (1024 * 1024)).toFixed(2)} MB`);
    doc.moveDown(2);

    // Uploads Section
    if (uploads && uploads.length > 0) {
      doc.addPage();
      doc.fontSize(16).font('Helvetica-Bold').text('Imágenes Subidas');
      doc.moveDown(1);
      
      uploads.forEach((upload, index) => {
        if (index > 0 && index % 8 === 0) {
          doc.addPage();
        }
        
        doc.fontSize(11).font('Helvetica-Bold').text(`${index + 1}. ${upload.filename || 'Sin nombre'}`);
        doc.fontSize(9).font('Helvetica');
        doc.text(`   ID: ${upload.id}`);
        doc.text(`   Tipo: ${upload.file_type || 'N/A'}`);
        doc.text(`   Tamaño: ${((upload.file_size || 0) / 1024).toFixed(2)} KB`);
        doc.text(`   Fecha: ${new Date(upload.created_at).toLocaleString('es-CO')}`);
        doc.text(`   URL Storage: ${upload.storage_path || 'N/A'}`);
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
        doc.text(`   Fecha: ${new Date(submission.created_at).toLocaleString('es-CO')}`);
        
        // Parse and display form data
        if (submission.form_data) {
          try {
            const formData = typeof submission.form_data === 'string' 
              ? JSON.parse(submission.form_data) 
              : submission.form_data;
            
            doc.text(`   Datos del formulario:`);
            Object.entries(formData).forEach(([key, value]) => {
              if (key !== 'photos' && typeof value !== 'object') {
                doc.text(`     • ${key}: ${value}`);
              }
            });
          } catch (e) {
            doc.text(`   Datos: ${submission.form_data}`);
          }
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
    if (!fs.existsSync(imagesDir)) {
      fs.mkdirSync(imagesDir, { recursive: true });
    }

    if (uploads && uploads.length > 0) {
      for (const upload of uploads) {
        if (upload.storage_path) {
          try {
            const { data: imageData, error: downloadError } = await supabase
              .storage
              .from('uploads')
              .download(upload.storage_path);
            
            if (!downloadError && imageData) {
              const buffer = Buffer.from(await imageData.arrayBuffer());
              const imagePath = path.join(imagesDir, upload.filename || `image_${upload.id}.jpg`);
              fs.writeFileSync(imagePath, buffer);
            }
          } catch (err) {
            console.error(`Error downloading image ${upload.id}:`, err);
          }
        }
      }
    }

    // Create README
    const readmePath = path.join(tempDir, 'README.txt');
    const readmeContent = `EXPORTACIÓN DE DATOS PERSONALES
================================

Generado el: ${new Date().toLocaleString('es-CO')}
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

    // Recent submissions (last 10)
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
      .limit(10);
    
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
      .select('id, name, email, created_at, credits, credits_last_reset, is_admin')
      .order('created_at', { ascending: false });
    
    if (error) throw error;

    // Get upload stats for each user
    const usersWithStats = await Promise.all(users.map(async (user) => {
      const { data: uploads, error: uploadsError } = await supabase
        .from('uploads')
        .select('size')
        .eq('owner_id', user.id);
      
      let totalPhotos = 0;
      let totalSize = 0;
      
      if (!uploadsError && uploads) {
        totalPhotos = uploads.length;
        totalSize = uploads.reduce((sum, upload) => sum + (upload.size || 0), 0);
      }
      
      return {
        ...user,
        total_photos: totalPhotos,
        total_size_bytes: totalSize,
        total_size_mb: (totalSize / (1024 * 1024)).toFixed(2)
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
        uploads(filename, custom_name),
        products(name, category)
      `)
      .order('created_at', { ascending: false });
    
    if (error) throw error;

    const submissionsWithInfo = submissions.map(sub => ({
      ...sub,
      user_name: sub.users?.name || 'Desconocido',
      user_email: sub.users?.email || 'N/A',
      photo_filename: sub.uploads?.custom_name || sub.uploads?.filename || 'Foto eliminada',
      product_name: sub.products?.name || null,
      product_category: sub.products?.category || null
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

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
