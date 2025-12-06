const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const steem = require('steem');
const cron = require('node-cron');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const CryptoJS = require('crypto-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(bodyParser.json());
app.use(session({ 
  secret: process.env.SESSION_SECRET || 'fallback-secret', 
  resave: false, 
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Postgres Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Init DB Tables (run once on startup)
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      steemit_username VARCHAR(100),
      posting_key_encrypted TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      title VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      tags JSONB NOT NULL DEFAULT '[]',
      schedule_date TIMESTAMP NOT NULL,
      status VARCHAR(50) DEFAULT 'scheduled',
      permlink VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}
initDB();

// Auth: Register (POST /auth/register {username, password, steemit_username, posting_key})
app.post('/auth/register', async (req, res) => {
  const { username, password, steemit_username, posting_key } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedKey = CryptoJS.AES.encrypt(posting_key, password).toString(); // Encrypt with user password
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, steemit_username, posting_key_encrypted) VALUES ($1, $2, $3, $4) RETURNING id',
      [username, hashedPassword, steemit_username, encryptedKey]
    );
    req.session.userId = result.rows[0].id;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Auth: Login (POST /auth/login {username, password})
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password_hash)) {
      req.session.userId = result.rows[0].id;
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Logout (POST /auth/logout)
app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Get User Info (GET /user)
app.get('/user', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  const result = await pool.query('SELECT id, username, steemit_username FROM users WHERE id = $1', [req.session.userId]);
  res.json(result.rows[0]);
});

// Create Post (POST /posts {title, body, tags: [], scheduleDate})
app.post('/posts', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  const { title, body, tags, scheduleDate } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO posts (user_id, title, body, tags, schedule_date) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.session.userId, title, body, JSON.stringify(tags), new Date(scheduleDate)]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Posts (GET /posts)
app.get('/posts', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  const result = await pool.query('SELECT * FROM posts WHERE user_id = $1 ORDER BY schedule_date ASC', [req.session.userId]);
  res.json(result.rows);
});

// Delete Post (DELETE /posts/:id)
app.delete('/posts/:id', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  await pool.query('DELETE FROM posts WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
  res.json({ success: true });
});

// Cron: Check and post due posts every minute
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const duePosts = await pool.query(
    'SELECT p.*, u.steemit_username, u.posting_key_encrypted FROM posts p JOIN users u ON p.user_id = u.id WHERE p.schedule_date <= $1 AND p.status = $2',
    [now, 'scheduled']
  );
  for (const post of duePosts.rows) {
    try {
      // For personal use, assume single user—decrypt key (in prod, fetch user password? Simplified: store decrypt key in env or skip for demo)
      // Note: For full security, you'd need to handle decryption dynamically; here, assume password is known or use env.
      // Placeholder: Use a fixed decrypt for demo—replace with real logic.
      const decryptedKey = process.env.DECRYPT_PASSWORD ? CryptoJS.AES.decrypt(post.posting_key_encrypted, process.env.DECRYPT_PASSWORD).toString(CryptoJS.enc.Utf8) : '';
      if (!decryptedKey) continue;

      const permlink = `${title.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`;
      const operations = [['comment', {
        parent_author: '',
        parent_permlink: post.tags[0] || 'steemit',
        author: post.steemit_username,
        permlink,
        title: post.title,
        body: post.body,
        json_metadata: JSON.stringify({ tags: post.tags })
      }]];
      steem.broadcast.operations(operations, decryptedKey, async (err, result) => {
        if (!err) {
          await pool.query('UPDATE posts SET status = $1, permlink = $2 WHERE id = $3', ['posted', permlink, post.id]);
          console.log(`Posted: ${post.title}`);
        } else {
          await pool.query('UPDATE posts SET status = $1 WHERE id = $2', ['failed', post.id]);
          console.error(`Post failed: ${err}`);
        }
      });
    } catch (err) {
      console.error('Cron error:', err);
    }
  }
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
