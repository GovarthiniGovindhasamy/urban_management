const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const port = 5000;

// Middleware — allow all origins so phones on same WiFi can reach the API
app.use(cors({ origin: '*' }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// MySQL Database Connection (use env vars on Render, fallback to local for dev)
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306'),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '1234',
  database: process.env.DB_NAME || 'urban_db',
  ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : undefined
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL: ', err);
    return;
  }
  console.log('Connected to MySQL Database: urban_db');
});

// ===================================
// AUTHENTICATION ROUTES
// ===================================

// Register User
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`;
    
    db.query(query, [username, email, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'Username or Email already exists.' });
        }
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ message: 'User registered successfully!' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login User
app.post('/api/login', (req, res) => {
  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({ error: 'Request body is missing. Send JSON with Content-Type: application/json' });
  }

  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const query = `SELECT * FROM users WHERE email = ?`;
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (isMatch) {
      res.status(200).json({
        message: 'Login successful',
        userId: user.user_id,
        username: user.username
      });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  });
});

// Worker Login
app.post('/api/worker/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const query = `SELECT * FROM workers WHERE email = ?`;
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid worker credentials' });

    const worker = results[0];
    let isMatch = false;
    if (worker.password_hash && worker.password_hash.startsWith('$2')) {
      isMatch = await bcrypt.compare(password, worker.password_hash);
    } else {
      isMatch = (password === worker.password_hash);
    }
    
    if (isMatch) {
      res.status(200).json({ message: 'Login successful', workerId: worker.worker_id, name: worker.name, phone: worker.phone, email: worker.email });
    } else {
      res.status(401).json({ error: 'Invalid worker credentials' });
    }
  });
});

// ===================================
// COMPLAINTS ROUTES
// ===================================

// Submit a new Complaint
app.post('/api/complaints', (req, res) => {
  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({ error: 'Request body is missing.' });
  }

  const {
    userId, title, category, description,
    location, area, pincode, landmark, ward,
    latitude, longitude, priority, images
  } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required to submit a complaint.' });
  }
  if (!title || !description) {
    return res.status(400).json({ error: 'Title and description are required.' });
  }

  // Serialize images array to JSON string for LONGTEXT storage
  const imagesJson = images && images.length > 0 ? JSON.stringify(images) : null;

  const query = `
    INSERT INTO complaints 
      (user_id, title, category, description, location, area, pincode, landmark, ward, latitude, longitude, priority, images)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.query(query,
    [userId, title, category, description, location, area, pincode, landmark, ward, latitude, longitude, priority || 'medium', imagesJson],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({
        message: 'Complaint submitted successfully!',
        complaintId: result.insertId
      });
    }
  );
});

// Get all Complaints for a User
app.get('/api/complaints/:userId', (req, res) => {
  const userId = req.params.userId;
  const query = `
    SELECT complaint_id, title, category, description, location,
           area, pincode, landmark, ward, latitude, longitude,
           priority, status, created_at, proof_photo
    FROM complaints
    WHERE user_id = ?
    ORDER BY created_at DESC
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(200).json(results);
  });
});

// ===================================
// ADMIN ROUTES
// ===================================

// Get all complaints for Admin (with user info)
app.get('/api/admin/complaints', (req, res) => {
  const query = `
    SELECT c.complaint_id, c.title, c.category, c.description, c.location,
           c.area, c.pincode, c.landmark, c.ward, c.latitude, c.longitude,
           c.priority, c.status, c.created_at, c.proof_photo,
           c.worker_name, c.worker_phone, c.expected_from_date, c.expected_to_date,
           u.username, u.email
    FROM complaints c
    JOIN users u ON c.user_id = u.user_id
    ORDER BY c.created_at DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(200).json(results);
  });
});

// Update complaint status (Admin)
// Includes full SMS detailed payload for 'Assigned' status
app.put('/api/admin/complaints/:id/status', (req, res) => {
  const complaintId = req.params.id;
  const { status, worker_name, worker_phone, from_date, to_date } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status is required.' });
  }

  // Update logic mapped with worker details if assigned
  let query = `UPDATE complaints SET status = ? WHERE complaint_id = ?`;
  let queryParams = [status, complaintId];
  if (worker_name) {
    query = `UPDATE complaints SET status = ?, worker_name = ?, worker_phone = ?, expected_from_date = ?, expected_to_date = ? WHERE complaint_id = ?`;
    queryParams = [status, worker_name, worker_phone, from_date || null, to_date || null, complaintId];
  }
  
  db.query(query, queryParams, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }

    // Trigger SMS if status updated to 'Assigned' and we have phone
    if (status === 'Assigned' && worker_phone) {
      db.query(`SELECT * FROM complaints WHERE complaint_id = ?`, [complaintId], (err2, rows) => {
        if (!err2 && rows.length > 0) {
          const comp = rows[0];
          try {
            const client = require('twilio')(
              process.env.TWILIO_ACCOUNT_SID || 'AC_dummy123',
              process.env.TWILIO_AUTH_TOKEN || 'test_token'
            );

            const smsText = `🚨 URBAN DRAINAGE ALERT 🚨\nNew Assignment: #${complaintId}\nCategory: ${comp.category}\nPriority: ${comp.priority}\nLocation: ${comp.area || comp.location}\nDetails: ${comp.description}\nLogin for Map view.`;
            
            if (!process.env.TWILIO_ACCOUNT_SID) {
              console.log('\n=======================================');
              console.log('📱 [MOCK SMS DISPATCHED]');
              console.log(`To: ${worker_phone}`);
              console.log(`Message:\n${smsText}`);
              console.log('=======================================\n');
            } else {
              client.messages.create({
                body: smsText,
                from: process.env.TWILIO_PHONE_NUMBER,
                to: worker_phone
              }).then(message => console.log('SMS sent! SID:', message.sid));
            }
          } catch (smsErr) {
            console.error('Twilio SMS Error:', smsErr);
          }
        }
      });
    }

    res.status(200).json({ message: 'Complaint status updated successfully!' });
  });
});

// Delete complaint (Admin Reject)
app.delete('/api/admin/complaints/:id', (req, res) => {
  const complaintId = req.params.id;
  const query = `DELETE FROM complaints WHERE complaint_id = ?`;
  db.query(query, [complaintId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(200).json({ message: 'Complaint deleted successfully!' });
  });
});

// Get all workers (with location)
app.get('/api/workers', (req, res) => {
  const query = 'SELECT worker_id, name, phone, email, location FROM workers ORDER BY name';
  db.query(query, (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'Database error' }); }
    res.status(200).json(results);
  });
});

// Get workers sorted by location match to complaint area
// Returns { exact: [...], others: [...] }
app.get('/api/workers/by-location', (req, res) => {
  const area = (req.query.area || '').trim().toLowerCase();

  const query = 'SELECT worker_id, name, phone, email, location FROM workers ORDER BY name';
  db.query(query, (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'Database error' }); }

    if (!area) {
      // No area provided — return all as "others"
      return res.status(200).json({ exact: [], others: results });
    }

    const exact = [];
    const others = [];

    results.forEach(w => {
      const workerCity = (w.location || '').toLowerCase();
      // Match if worker city appears inside complaint area string or vice versa
      if (area.includes(workerCity) || workerCity.includes(area)) {
        exact.push(w);
      } else {
        others.push(w);
      }
    });

    res.status(200).json({ exact, others });
  });
});

// ===================================
// WORKER ROUTES
// ===================================

app.get('/api/worker/complaints/:phone', (req, res) => {
  const phone = req.params.phone;
  // + could be omitted in URL parms usually, but react deals with it
  // Actually we need to make sure URL encoded works or just match by exact string
  const query = `SELECT * FROM complaints WHERE worker_phone = ? AND status != 'Pending' ORDER BY created_at DESC`;
  db.query(query, [phone], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.status(200).json(results);
  });
});

app.put('/api/worker/complaints/:id/start', (req, res) => {
  const complaintId = req.params.id;
  const query = `UPDATE complaints SET status = 'In Progress' WHERE complaint_id = ?`;
  db.query(query, [complaintId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.status(200).json({ message: 'Complaint work started!' });
  });
});

app.put('/api/worker/complaints/:id/resolve', (req, res) => {
  const complaintId = req.params.id;
  const { proof_photo } = req.body;

  if (!proof_photo) return res.status(400).json({ error: 'Proof photo is required.' });

  const query = `UPDATE complaints SET status = 'Worker Resolved', proof_photo = ? WHERE complaint_id = ?`;
  db.query(query, [proof_photo, complaintId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.status(200).json({ message: 'Complaint resolved by worker with proof!' });
  });
});

// Listen on 0.0.0.0 so phones on the same WiFi can reach the backend
app.listen(port, '0.0.0.0', () => {
  console.log(`Backend server running on http://localhost:${port}`);
  console.log(`📱 Mobile access: http://10.48.44.85:${port}`);
});
