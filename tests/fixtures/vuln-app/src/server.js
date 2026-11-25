const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const db = require('./lib/db');
const { requireAuth } = require('./lib/auth');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Product search — public
app.get('/api/search', async (req, res) => {
  const q = req.query.q || '';
  const rows = await db.query("SELECT * FROM products WHERE name LIKE '%" + q + "%'");
  res.json(rows);
});

// Image thumbnails
app.get('/api/thumb', (req, res) => {
  exec(`convert uploads/${req.query.file} -resize 200x200 /tmp/thumb.png`, (err) => {
    if (err) return res.status(500).send(err.stack);
    res.sendFile('/tmp/thumb.png');
  });
});

app.get('/api/files', requireAuth, (req, res) => {
  const p = path.join(__dirname, '..', 'uploads', req.query.name);
  res.send(fs.readFileSync(p));
});

app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  res.json(order);
});

app.post('/api/validate-email', (req, res) => {
  const ok = /^([a-zA-Z0-9]+)*@example\.com$/.test(req.body.email);
  res.json({ ok });
});

app.listen(3000);
