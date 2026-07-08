const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
const { Expo } = require('expo-server-sdk');
let expo = new Expo();

// Ensure critical environment variables are loaded
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  console.error('FATAL ERROR: DATABASE_URL and JWT_SECRET are required.');
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Note: Consider using AWS S3 for images rather than base64 DB storage in prod.

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { 
    rejectUnauthorized: false 
  },
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ==========================================
// 1. AUTHENTICATION & PROFILE ROUTES
// ==========================================

app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  
  const normalizedEmail = email.trim().toLowerCase();
  if (!isValidEmail(normalizedEmail)) return res.status(400).json({ error: 'Invalid email format.' });

  try {
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (userExists.rows.length > 0) return res.status(400).json({ error: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name',
      [normalizedEmail, passwordHash, name.trim()]
    );

    const user = newUser.rows[0];
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '72h' });
    res.status(201).json({ message: 'User created', token, user });
  } catch (error) { 
    console.error('Registration Error:', error);
    res.status(500).json({ error: 'Internal server error.' }); 
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  
  const normalizedEmail = email.trim().toLowerCase();

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    if (userResult.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '72h' });
    res.json({ message: 'Login successful', token });
  } catch (error) { 
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Internal server error.' }); 
  }
});

app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT id, email, name, avatar_url, created_at FROM users WHERE id = $1', [req.user.userId]);
    res.json({ user: userResult.rows[0] });
  } catch (error) { 
    console.error('Dashboard Fetch Error:', error);
    res.status(500).json({ error: 'Server error' }); 
  }
});

app.put('/profile/username', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE users SET name = $1 WHERE id = $2', [req.body.name, req.user.userId]);
    res.json({ message: 'Username updated successfully.' });
  } catch (error) { 
    console.error('Update Username Error:', error);
    res.status(500).json({ error: 'Server error' }); 
  }
});

app.put('/profile/push-token', authenticateToken, async (req, res) => {
  const { pushToken } = req.body;
  try {
    await pool.query('UPDATE users SET push_token = $1 WHERE id = $2', [pushToken, req.user.userId]);
    res.json({ message: 'Token saved' });
  } catch (error) { 
    console.error('Push Token Error:', error);
    res.status(500).json({ error: 'Failed to save token' }); 
  }
});

app.put('/profile/password', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
    const isMatch = await bcrypt.compare(req.body.currentPassword, userRes.rows[0].password_hash);
    if (!isMatch) return res.status(400).json({ error: 'Incorrect current password.' });

    const newHash = await bcrypt.hash(req.body.newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.user.userId]);
    res.json({ message: 'Password updated successfully.' });
  } catch (error) { 
    console.error('Update Password Error:', error);
    res.status(500).json({ error: 'Server error' }); 
  }
});

app.put('/profile/avatar', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [req.body.avatar_url, req.user.userId]);
    res.json({ message: 'Avatar updated successfully.' });
  } catch (error) { 
    console.error('Update Avatar Error:', error);
    res.status(500).json({ error: 'Server error' }); 
  }
});

// ==========================================
// 2. NETWORK / FRIENDS ROUTES
// ==========================================

app.get('/users/all', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.name, f.status,
             CASE WHEN f.requester_id = $1 THEN true ELSE false END as is_outgoing
      FROM users u
      LEFT JOIN friendships f ON 
        (f.requester_id = $1 AND f.receiver_id = u.id) OR 
        (f.requester_id = u.id AND f.receiver_id = $1)
      WHERE u.id != $1 
      AND (f.status IS NULL OR f.status = 'pending')
    `, [req.user.userId]);
    res.json({ users: result.rows });
  } catch (error) { 
    console.error('Fetch Users Error:', error);
    res.status(500).json({ error: 'Failed to fetch users' }); 
  }
});

app.post('/friends/request', authenticateToken, async (req, res) => {
  const { receiverId } = req.body;
  try {
    await pool.query('INSERT INTO friendships (requester_id, receiver_id) VALUES ($1, $2)', [req.user.userId, receiverId]);
    res.json({ message: 'Request sent' });
  } catch (error) { 
    console.error('Friend Request Error:', error);
    res.status(500).json({ error: 'Failed to send request' }); 
  }
});

app.post('/friends/accept', authenticateToken, async (req, res) => {
  const { requesterId } = req.body;
  try {
    await pool.query('UPDATE friendships SET status = $1 WHERE requester_id = $2 AND receiver_id = $3', ['accepted', requesterId, req.user.userId]);
    res.json({ message: 'Friend added' });
  } catch (error) { 
    console.error('Accept Friend Error:', error);
    res.status(500).json({ error: 'Failed to accept' }); 
  }
});

app.get('/friends', authenticateToken, async (req, res) => {
  try {
    const pending = await pool.query(`
      SELECT u.id, u.email, u.name FROM friendships f
      JOIN users u ON f.requester_id = u.id
      WHERE f.receiver_id = $1 AND f.status = 'pending'
    `, [req.user.userId]);

    const active = await pool.query(`
      SELECT u.id, u.email, u.name FROM friendships f
      JOIN users u ON (f.requester_id = u.id OR f.receiver_id = u.id)
      WHERE (f.requester_id = $1 OR f.receiver_id = $1) 
      AND f.status = 'accepted' AND u.id != $1
    `, [req.user.userId]);

    res.json({ pendingRequests: pending.rows, activeConnections: active.rows });
  } catch (error) { 
    console.error('Fetch Friends Error:', error);
    res.status(500).json({ error: 'Failed to load network' }); 
  }
});

// ==========================================
// 3. SNAPS ROUTES 
// ==========================================

app.post('/snaps', authenticateToken, async (req, res) => {
  const { payload, visibility } = req.body; 
  try {
    // 1. Friend check logic (From previous step)
    if (visibility === 'friends') {
      const friendsCheck = await pool.query(`
        SELECT 1 FROM friendships 
        WHERE (requester_id = $1 OR receiver_id = $1) AND status = 'accepted'
        LIMIT 1
      `, [req.user.userId]);

      if (friendsCheck.rows.length === 0) {
        return res.status(400).json({ error: 'You are unable to send snaps to friends, because you have 0 friends.' });
      }
    }

    // 2. Insert the snap
    await pool.query(
      'INSERT INTO snaps (sender_id, payload, visibility) VALUES ($1, $2, $3)',
      [req.user.userId, payload, visibility || 'global']
    );

    // 3. --- NEW NOTIFICATION LOGIC ---
    
    // Get sender's name for the notification
    const senderRes = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.userId]);
    const senderName = senderRes.rows[0].name;

    let targetUsersQuery = '';
    
    if (visibility === 'friends') {
      // Find push tokens of accepted friends
      targetUsersQuery = `
        SELECT u.push_token FROM users u
        JOIN friendships f ON (f.requester_id = u.id OR f.receiver_id = u.id)
        WHERE (f.requester_id = $1 OR f.receiver_id = $1)
        AND f.status = 'accepted' AND u.id != $1 AND u.push_token IS NOT NULL
      `;
    } else {
      // Global: Find push tokens of everyone except the sender
      targetUsersQuery = `SELECT push_token FROM users WHERE id != $1 AND push_token IS NOT NULL`;
    }

    const targetUsers = await pool.query(targetUsersQuery, [req.user.userId]);

    // Build the notification messages
    let messages = [];
    for (let user of targetUsers.rows) {
      if (!Expo.isExpoPushToken(user.push_token)) continue; // Skip invalid tokens
      
      messages.push({
        to: user.push_token,
        sound: 'default',
        title: visibility === 'friends' ? `New Snap from ${senderName} 🔒` : `Global Drop from ${senderName} 🌍`,
        body: 'Tap to view it before it disappears.',
      });
    }

    // Send them out in chunks (Expo requirement)
    let chunks = expo.chunkPushNotifications(messages);
    for (let chunk of chunks) {
      try {
        await expo.sendPushNotificationsAsync(chunk);
      } catch (error) {
        console.error('Error sending push chunk:', error);
      }
    }

    res.json({ message: 'Snap dropped to network and notified!' });
  } catch (error) { 
    console.error('Create Snap Error:', error);
    res.status(500).json({ error: 'Failed to send snap' }); 
  }
});

// ==========================================
// REPLACE THIS ROUTE IN server.js
// ==========================================

app.get('/snaps', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.id, s.payload, 
             (s.created_at AT TIME ZONE 'UTC') as created_at, 
             s.visibility, u.name as sender, u.avatar_url
      FROM snaps s
      JOIN users u ON s.sender_id = u.id
      WHERE s.created_at >= NOW() - INTERVAL '24 hours'
      /* Removed the 'AND s.sender_id != $1' line so you can see your own snaps */
      AND (
        s.visibility = 'global' 
        OR (
          s.visibility = 'friends' AND EXISTS (
            SELECT 1 FROM friendships f 
            WHERE f.status = 'accepted' 
            AND (
              (f.requester_id = $1 AND f.receiver_id = s.sender_id) OR 
              (f.requester_id = s.sender_id AND f.receiver_id = $1)
            )
          )
        )
      )
      ORDER BY s.created_at DESC
    `, [req.user.userId]);

    res.json({ inbox: result.rows });
  } catch (error) { 
    console.error('Fetch Snaps Error:', error);
    res.status(500).json({ error: 'Failed to load feed' }); 
  }
});

app.get('/profile/snaps', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, payload, (created_at AT TIME ZONE 'UTC') as created_at 
      FROM snaps 
      WHERE sender_id = $1 
      AND created_at >= NOW() - INTERVAL '24 hours'
      ORDER BY created_at DESC
    `, [req.user.userId]);
    res.json({ mySnaps: result.rows });
  } catch (error) { 
    console.error('Fetch Profile Snaps Error:', error);
    res.status(500).json({ error: 'Failed to load my snaps' }); 
  }
});

app.delete('/snaps/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM snaps WHERE id = $1 AND sender_id = $2', [req.params.id, req.user.userId]);
    res.json({ message: 'Snap deleted permanently.' });
  } catch (error) { 
    console.error('Delete Snap Error:', error);
    res.status(500).json({ error: 'Failed to delete snap' }); 
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));