// ============================================
// PandaHub Backend - server.js
// Node.js + Express + PostgreSQL
// ============================================
// Install: npm install express pg bcryptjs jsonwebtoken
//          multer cors dotenv uuid express-validator

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// DATABASE CONNECTION
// ============================================
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'pandahub',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Prevent DB errors from crashing the server
pool.on('error', (err) => {
  console.warn('⚠️ Database pool error (server continues running):', err.message);
});

pool.connect((err) => {
  if (err) console.warn('⚠️ DB not available:', err.message);
  else console.log('🐼 Connected to PostgreSQL database!');
});

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors({
  origin: '*',
  credentials: false
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', req.user?.id || 'temp');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB per file
  fileFilter: (req, file, cb) => {
    const blocked = ['.exe', '.bat', '.sh', '.cmd'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (blocked.includes(ext)) return cb(new Error('File type not allowed'));
    cb(null, true);
  }
});

// ============================================
// AUTH MIDDLEWARE
// ============================================
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'panda_secret_key_2024');
    const result = await pool.query(
      'SELECT id, username, email, display_name, avatar_url, bio, panda_badge FROM users WHERE id = $1',
      [decoded.userId]
    );
    if (!result.rows[0]) return res.status(401).json({ error: 'User not found' });
    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const optionalAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'panda_secret_key_2024');
      const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
      if (result.rows[0]) req.user = result.rows[0];
    }
  } catch {}
  next();
};

// ============================================
// HELPERS
// ============================================
const generateToken = (userId) =>
  jwt.sign({ userId }, process.env.JWT_SECRET || 'panda_secret_key_2024', { expiresIn: '7d' });

const paginate = (page = 1, limit = 20) => ({
  offset: (Math.max(1, parseInt(page)) - 1) * Math.min(100, parseInt(limit)),
  limit: Math.min(100, parseInt(limit))
});

// ============================================
// ROUTES: AUTH
// ============================================

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, display_name } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Username, email, and password are required' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!/^[a-zA-Z0-9_-]+$/.test(username))
      return res.status(400).json({ error: 'Username can only contain letters, numbers, _ and -' });

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]
    );
    if (existingUser.rows.length > 0)
      return res.status(409).json({ error: 'Username or email already taken' });

    const password_hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, display_name)
       VALUES ($1, $2, $3, $4) RETURNING id, username, email, display_name, panda_badge, created_at`,
      [username.toLowerCase(), email.toLowerCase(), password_hash, display_name || username]
    );

    const user = result.rows[0];
    const token = generateToken(user.id);
    res.status(201).json({ token, user });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $1', [email.toLowerCase()]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    const { password_hash, ...safeUser } = user;
    const token = generateToken(user.id);
    res.json({ token, user: safeUser });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({ user: req.user });
});

// ============================================
// ROUTES: USERS
// ============================================

// GET /api/users/:username
app.get('/api/users/:username', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, avatar_url, bio, panda_badge, created_at,
       (SELECT COUNT(*) FROM projects WHERE owner_id = u.id AND is_public = TRUE) as public_projects,
       (SELECT COUNT(*) FROM project_stars ps JOIN projects p ON ps.project_id = p.id WHERE p.owner_id = u.id) as total_stars
       FROM users u WHERE username = $1`, [req.params.username]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// PUT /api/users/me
app.put('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const { display_name, bio, avatar_url } = req.body;
    const result = await pool.query(
      `UPDATE users SET display_name = COALESCE($1, display_name),
       bio = COALESCE($2, bio), avatar_url = COALESCE($3, avatar_url),
       updated_at = NOW() WHERE id = $4
       RETURNING id, username, email, display_name, avatar_url, bio, panda_badge`,
      [display_name, bio, avatar_url, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ============================================
// ROUTES: WORKSPACES
// ============================================

// GET /api/workspaces - list user's workspaces
app.get('/api/workspaces', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT w.*, wm.role,
       (SELECT COUNT(*) FROM workspace_members WHERE workspace_id = w.id) as member_count,
       (SELECT COUNT(*) FROM projects WHERE workspace_id = w.id) as project_count
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       WHERE wm.user_id = $1
       ORDER BY w.created_at DESC`, [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch workspaces' });
  }
});

// POST /api/workspaces
app.post('/api/workspaces', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, description, is_public } = req.body;
    if (!name) return res.status(400).json({ error: 'Workspace name is required' });

    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const existingSlug = await pool.query('SELECT id FROM workspaces WHERE slug = $1', [slug]);
    const finalSlug = existingSlug.rows.length > 0 ? `${slug}-${uuidv4().slice(0,6)}` : slug;

    await client.query('BEGIN');
    const ws = await client.query(
      `INSERT INTO workspaces (owner_id, name, slug, description, is_public)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, name, finalSlug, description, is_public !== false]
    );
    await client.query(
      `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'owner')`,
      [ws.rows[0].id, req.user.id]
    );
    await client.query('COMMIT');
    res.status(201).json(ws.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to create workspace' });
  } finally {
    client.release();
  }
});

// GET /api/workspaces/:slug
app.get('/api/workspaces/:slug', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT w.*,
       (SELECT COUNT(*) FROM workspace_members WHERE workspace_id = w.id) as member_count,
       (SELECT COUNT(*) FROM projects WHERE workspace_id = w.id) as project_count
       FROM workspaces w WHERE w.slug = $1`, [req.params.slug]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Workspace not found' });
    const ws = result.rows[0];
    if (!ws.is_public && (!req.user)) return res.status(403).json({ error: 'Private workspace' });

    const members = await pool.query(
      `SELECT u.id, u.username, u.display_name, u.avatar_url, u.panda_badge, wm.role, wm.joined_at
       FROM workspace_members wm JOIN users u ON wm.user_id = u.id
       WHERE wm.workspace_id = $1 ORDER BY wm.joined_at`, [ws.id]
    );
    res.json({ ...ws, members: members.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch workspace' });
  }
});

// ============================================
// ROUTES: TEAM INVITATIONS
// ============================================

// POST /api/workspaces/:id/invite
app.post('/api/workspaces/:id/invite', authMiddleware, async (req, res) => {
  try {
    const { role, invite_email } = req.body;
    const memberCheck = await pool.query(
      `SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );
    if (!memberCheck.rows[0] || !['owner', 'admin'].includes(memberCheck.rows[0].role))
      return res.status(403).json({ error: 'Only owners and admins can invite' });

    const result = await pool.query(
      `INSERT INTO team_invitations (workspace_id, invited_by, invite_email, role)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, req.user.id, invite_email, role || 'member']
    );
    const invite = result.rows[0];
    const link = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/invite/${invite.invite_token}`;
    res.json({ invite, link });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create invitation' });
  }
});

// POST /api/invites/:token/accept
app.post('/api/invites/:token/accept', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const invite = await pool.query(
      `SELECT * FROM team_invitations WHERE invite_token = $1 AND used_at IS NULL AND expires_at > NOW()`,
      [req.params.token]
    );
    if (!invite.rows[0]) return res.status(404).json({ error: 'Invalid or expired invitation' });
    const inv = invite.rows[0];

    await client.query('BEGIN');
    await client.query(
      `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3)
       ON CONFLICT (workspace_id, user_id) DO NOTHING`,
      [inv.workspace_id, req.user.id, inv.role]
    );
    await client.query(
      `UPDATE team_invitations SET used_at = NOW(), used_by = $1 WHERE id = $2`,
      [req.user.id, inv.id]
    );
    await client.query('COMMIT');

    const ws = await pool.query('SELECT * FROM workspaces WHERE id = $1', [inv.workspace_id]);
    res.json({ message: 'Joined workspace!', workspace: ws.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to accept invitation' });
  } finally {
    client.release();
  }
});

// GET /api/invites/:token - preview invite
app.get('/api/invites/:token', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ti.*, w.name as workspace_name, w.description as workspace_desc,
       w.slug as workspace_slug, u.display_name as invited_by_name, u.username as invited_by_username
       FROM team_invitations ti
       JOIN workspaces w ON ti.workspace_id = w.id
       JOIN users u ON ti.invited_by = u.id
       WHERE ti.invite_token = $1 AND ti.used_at IS NULL AND ti.expires_at > NOW()`,
      [req.params.token]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Invalid or expired invitation' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch invitation' });
  }
});

// ============================================
// ROUTES: PROJECTS
// ============================================

// GET /api/projects - public explore feed
app.get('/api/projects', optionalAuth, async (req, res) => {
  try {
    const { page = 1, limit = 12, search, tag, language, sort = 'latest' } = req.query;
    const { offset, limit: lim } = paginate(page, limit);

    let query = `
      SELECT p.*, u.username, u.display_name, u.avatar_url as owner_avatar,
      w.name as workspace_name, w.slug as workspace_slug,
      EXISTS(SELECT 1 FROM project_stars WHERE project_id = p.id AND user_id = $3) as is_starred
      FROM projects p
      JOIN users u ON p.owner_id = u.id
      LEFT JOIN workspaces w ON p.workspace_id = w.id
      WHERE p.is_public = TRUE
    `;
    const params = [lim, offset, req.user?.id || null];
    let paramIdx = 4;

    if (search) {
      query += ` AND (p.name ILIKE $${paramIdx} OR p.description ILIKE $${paramIdx})`;
      params.push(`%${search}%`);
      paramIdx++;
    }
    if (tag) {
      query += ` AND $${paramIdx} = ANY(p.tags)`;
      params.push(tag);
      paramIdx++;
    }
    if (language) {
      query += ` AND p.language ILIKE $${paramIdx}`;
      params.push(language);
      paramIdx++;
    }

    const orderMap = {
      latest: 'p.created_at DESC',
      stars: 'p.stars_count DESC',
      forks: 'p.forks_count DESC',
      views: 'p.views_count DESC'
    };
    query += ` ORDER BY ${orderMap[sort] || 'p.created_at DESC'} LIMIT $1 OFFSET $2`;

    const [projects, total] = await Promise.all([
      pool.query(query, params),
      pool.query(`SELECT COUNT(*) FROM projects WHERE is_public = TRUE`)
    ]);

    res.json({ projects: projects.rows, total: parseInt(total.rows[0].count), page: parseInt(page), limit: lim });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// POST /api/projects
app.post('/api/projects', authMiddleware, upload.array('files', 20), async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, description, readme, is_public, tags, language, workspace_id } = req.body;
    if (!name) return res.status(400).json({ error: 'Project name required' });

    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

    await client.query('BEGIN');
    const proj = await client.query(
      `INSERT INTO projects (owner_id, workspace_id, name, slug, description, readme, is_public, tags, language)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [req.user.id, workspace_id || null, name, slug, description, readme, is_public !== 'false',
       tags ? JSON.parse(tags) : [], language]
    );

    const project = proj.rows[0];

    if (req.files?.length > 0) {
      for (const file of req.files) {
        await client.query(
          `INSERT INTO project_files (project_id, filename, filepath, file_type, file_size, storage_url, uploaded_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [project.id, file.originalname, file.filename, file.mimetype, file.size,
           `/uploads/${req.user.id}/${file.filename}`, req.user.id]
        );
      }
    }

    await client.query('COMMIT');
    res.status(201).json(project);
  } catch (err) {
    await client.query('ROLLBACK');
    if (req.files) req.files.forEach(f => fs.unlink(f.path, () => {}));
    console.error(err);
    res.status(500).json({ error: 'Failed to create project' });
  } finally {
    client.release();
  }
});

// GET /api/projects/:username/:slug
app.get('/api/projects/:username/:slug', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.username, u.display_name, u.avatar_url as owner_avatar, u.panda_badge,
       w.name as workspace_name, w.slug as workspace_slug,
       EXISTS(SELECT 1 FROM project_stars WHERE project_id = p.id AND user_id = $3) as is_starred
       FROM projects p
       JOIN users u ON p.owner_id = u.id
       LEFT JOIN workspaces w ON p.workspace_id = w.id
       WHERE u.username = $1 AND p.slug = $2`,
      [req.params.username, req.params.slug, req.user?.id || null]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Project not found' });
    const project = result.rows[0];
    if (!project.is_public && project.owner_id !== req.user?.id)
      return res.status(403).json({ error: 'Private project' });

    // Increment views
    await pool.query('UPDATE projects SET views_count = views_count + 1 WHERE id = $1', [project.id]);

    const files = await pool.query(
      'SELECT * FROM project_files WHERE project_id = $1 ORDER BY created_at', [project.id]
    );
    const comments = await pool.query(
      `SELECT c.*, u.username, u.display_name, u.avatar_url, u.panda_badge
       FROM comments c JOIN users u ON c.user_id = u.id
       WHERE c.project_id = $1 AND c.parent_id IS NULL ORDER BY c.created_at DESC LIMIT 20`,
      [project.id]
    );

    res.json({ ...project, files: files.rows, comments: comments.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

// POST /api/projects/:id/star
app.post('/api/projects/:id/star', authMiddleware, async (req, res) => {
  try {
    const existing = await pool.query(
      'SELECT id FROM project_stars WHERE project_id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    if (existing.rows[0]) {
      await pool.query('DELETE FROM project_stars WHERE project_id = $1 AND user_id = $2',
        [req.params.id, req.user.id]);
      res.json({ starred: false });
    } else {
      await pool.query('INSERT INTO project_stars (project_id, user_id) VALUES ($1, $2)',
        [req.params.id, req.user.id]);
      res.json({ starred: true });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle star' });
  }
});

// POST /api/projects/:id/fork
app.post('/api/projects/:id/fork', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const original = await pool.query('SELECT * FROM projects WHERE id = $1', [req.params.id]);
    if (!original.rows[0]) return res.status(404).json({ error: 'Project not found' });
    const orig = original.rows[0];

    const slug = `${orig.slug}-fork-${uuidv4().slice(0,6)}`;
    await client.query('BEGIN');
    const forked = await client.query(
      `INSERT INTO projects (owner_id, name, slug, description, readme, is_public, tags, language)
       VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7) RETURNING *`,
      [req.user.id, `${orig.name} (fork)`, slug, orig.description, orig.readme, orig.tags, orig.language]
    );
    await client.query(
      `INSERT INTO project_forks (original_project_id, forked_project_id, forked_by)
       VALUES ($1, $2, $3)`,
      [orig.id, forked.rows[0].id, req.user.id]
    );
    await client.query('COMMIT');
    res.status(201).json(forked.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed to fork project' });
  } finally {
    client.release();
  }
});

// GET /api/projects/:id/download
app.get('/api/projects/:id/download', optionalAuth, async (req, res) => {
  try {
    const files = await pool.query(
      'SELECT * FROM project_files WHERE project_id = $1', [req.params.id]
    );
    await pool.query('UPDATE projects SET downloads_count = downloads_count + 1 WHERE id = $1', [req.params.id]);
    res.json({ files: files.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get download info' });
  }
});

// ============================================
// ROUTES: COMMENTS
// ============================================

// POST /api/projects/:id/comments
app.post('/api/projects/:id/comments', authMiddleware, async (req, res) => {
  try {
    const { content, parent_id } = req.body;
    if (!content) return res.status(400).json({ error: 'Comment content required' });
    const result = await pool.query(
      `INSERT INTO comments (project_id, user_id, content, parent_id)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, req.user.id, content, parent_id || null]
    );
    const comment = await pool.query(
      `SELECT c.*, u.username, u.display_name, u.avatar_url, u.panda_badge
       FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = $1`,
      [result.rows[0].id]
    );
    res.status(201).json(comment.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

// ============================================
// ROUTES: PANDA CHATBOT
// ============================================

// POST /api/chat
app.post('/api/chat', authMiddleware, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    // Save user message
    await pool.query(
      'INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)',
      [req.user.id, 'user', message]
    );

    // Panda bot response (simple rule-based + smart fallbacks)
    const botReply = getPandaBotResponse(message, req.user);

    // Save bot response
    await pool.query(
      'INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)',
      [req.user.id, 'assistant', botReply]
    );

    res.json({ reply: botReply });
  } catch (err) {
    res.status(500).json({ error: 'Chat failed' });
  }
});

// GET /api/chat/history
app.get('/api/chat/history', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT role, content, created_at FROM chat_messages
       WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(result.rows.reverse());
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

// Panda bot logic
function getPandaBotResponse(msg, user) {
  const m = msg.toLowerCase();
  const name = user.display_name || user.username;

  if (m.includes('hello') || m.includes('hi') || m.includes('hey'))
    return `🐼 Hewwo ${name}! I'm PandaBot, your fluffy code assistant! How can I help you today? *munches bamboo*`;
  if (m.includes('how to') && m.includes('project'))
    return `🐼 Creating a project is easy! Click the **+ New Project** button on your dashboard, give it a name, upload your files, and add a description. You can also add it to a workspace! Need more help?`;
  if (m.includes('workspace'))
    return `🐼 Workspaces are like bamboo groves — they group your projects and team together! You can create one from the dashboard, then invite teammates via the special invite link. 🎋`;
  if (m.includes('invite') || m.includes('team'))
    return `🐼 To invite someone: go to your workspace → click **Invite Members** → copy the invite link and share it! They can join even without an account first. 🐼✉️`;
  if (m.includes('star'))
    return `🐼 Stars are how you bookmark projects you love! Click the ⭐ star button on any project page. Your starred projects appear in your profile!`;
  if (m.includes('fork'))
    return `🐼 Forking copies a project to your account so you can modify it freely. It's great for building on others' work! Click the **Fork** button on any public project. 🍴`;
  if (m.includes('download'))
    return `🐼 You can download project files from the project page — click **Download Files**. All uploaded files will be listed there! 📦`;
  if (m.includes('profile'))
    return `🐼 Edit your profile by clicking your avatar in the top right → **Settings**. You can update your display name, bio, and avatar! You'll earn panda badges as you contribute more 🐼🌟`;
  if (m.includes('panda') || m.includes('bamboo'))
    return `🐼 *squeaks excitedly* Did someone say PANDA?! I LOVE pandas! 🎋 We're the fluffiest, most efficient code reviewers in the animal kingdom!`;
  if (m.includes('thank'))
    return `🐼 You're so welcome! That makes this little panda very happy! 🐼💚 Is there anything else I can help with?`;
  if (m.includes('bug') || m.includes('error') || m.includes('problem'))
    return `🐼 Oh no, a bug! 🐛 Can you describe what's happening? Check the browser console for error messages, and make sure your API server is running. I'll help sniff it out!`;
  if (m.includes('public') || m.includes('private'))
    return `🐼 You can set any project as **Public** (visible to everyone) or **Private** (only you and your workspace members). Toggle it during creation or in project settings! 🔒`;

  const defaults = [
    `🐼 Hmm, I'm not sure about that one! Try asking about projects, workspaces, invites, or stars. *adjusts bamboo hat*`,
    `🐼 Great question! I'm still learning... Try asking me about how to use PandaHub features! 🌿`,
    `🐼 *chews bamboo thoughtfully* That's beyond my current bamboo knowledge... Try the docs or ask me about features!`
  ];
  return defaults[Math.floor(Math.random() * defaults.length)];
}

// ============================================
// ROUTES: NOTIFICATIONS
// ============================================

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.put('/api/notifications/read', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET is_read = TRUE WHERE user_id = $1', [req.user.id]);
    res.json({ message: 'Marked all as read' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update notifications' });
  }
});



// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: '🐼 PandaHub is alive and eating bamboo!' });
});

// ============================================
// ERROR HANDLER
// ============================================
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: 'File too large (max 50MB)' });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================

// Prevent server from crashing on unhandled errors
process.on('uncaughtException', (err) => {
  console.error('⚠️ Uncaught exception (server continues):', err.message);
});
process.on('unhandledRejection', (err) => {
  console.error('⚠️ Unhandled rejection (server continues):', err.message || err);
});

app.listen(PORT, () => {
  console.log(`🐼 PandaHub backend running on http://localhost:${PORT}`);
});

module.exports = app;