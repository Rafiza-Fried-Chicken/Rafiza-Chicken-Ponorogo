// FILE: app.js
/**
 * README:
 * 1) Run `npm init -y`
 * 2) Run `npm i express cookie-session bcryptjs uuid`
 * 3) Run `node app.js`
 * 4) Open http://localhost:3000/dashboard/index.html
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const cookieSession = require('cookie-session');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

const USERS_FILE = path.join(__dirname, 'users.json');
const ORDERS_FILE = path.join(__dirname, 'orders.json');
const CONTACTS_LOG = path.join(__dirname, 'contacts.log');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieSession({
  name: 'session',
  keys: ['secretKey1', 'secretKey2'],
  maxAge: 24 * 60 * 60 * 1000 // 1 day
}));

// Serve static files from dashboard folder
app.use('/dashboard', express.static(path.join(__dirname, 'dashboard')));

// Helper functions
function readJSON(file) {
  try {
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function sanitizeString(str) {
  return String(str).replace(/[<>"'`]/g, '');
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function authMiddleware(req, res, next) {
  if (req.session && req.session.userId) {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.session.userId);
    if (user) {
      req.user = user;
      return next();
    }
  }
  res.status(401).json({ ok: false, error: 'Unauthorized' });
}

// Rate limit for auth endpoints (simple in-memory)
const rateLimitMap = {};
function rateLimit(key, limit = 5, windowMs = 60000) {
  const now = Date.now();
  if (!rateLimitMap[key]) {
    rateLimitMap[key] = [];
  }
  rateLimitMap[key] = rateLimitMap[key].filter(ts => now - ts < windowMs);
  if (rateLimitMap[key].length >= limit) {
    return false;
  }
  rateLimitMap[key].push(now);
  return true;
}

// API Routes

// POST /api/register
app.post('/api/register', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`register-${ip}`)) {
    return res.status(429).json({ ok: false, error: 'Too many requests' });
  }

  let { name, email, password } = req.body;
  name = sanitizeString(name || '').trim();
  email = sanitizeString(email || '').toLowerCase().trim();
  password = String(password || '');

  if (!name || !email || !password) {
    return res.status(400).json({ ok: false, error: 'All fields are required' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ ok: false, error: 'Invalid email format' });
  }
  if (password.length < 8) {
    return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters' });
  }

  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ ok: false, error: 'Email already registered' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const newUser  = {
    id: uuidv4(),
    name,
    email,
    passwordHash,
    createdAt: new Date().toISOString(),
    plan: 'free'
  };
  users.push(newUser );
  writeJSON(USERS_FILE, users);

  res.status(201).json({ ok: true });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`login-${ip}`)) {
    return res.status(429).json({ ok: false, error: 'Too many requests' });
  }

  let { email, password } = req.body;
  email = sanitizeString(email || '').toLowerCase().trim();
  password = String(password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password required' });
  }

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ ok: false, error: 'Invalid email or password' });
  }

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(400).json({ ok: false, error: 'Invalid email or password' });
  }

  req.session.userId = user.id;
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email } });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// GET /api/me
app.get('/api/me', authMiddleware, (req, res) => {
  const { id, name, email, plan, createdAt } = req.user;
  res.json({ ok: true, user: { id, name, email, plan, createdAt } });
});

// GET /api/orders/me
app.get('/api/orders/me', authMiddleware, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const userOrders = orders.filter(o => o.userId === req.user.id);
  res.json({ ok: true, orders: userOrders });
});

// POST /api/checkout
app.post('/api/checkout', authMiddleware, (req, res) => {
  let { items, address, paymentMethod } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ ok: false, error: 'Cart items required' });
  }
  address = sanitizeString(address || '').trim();
  paymentMethod = sanitizeString(paymentMethod || '').trim();

  if (!address || !paymentMethod) {
    return res.status(400).json({ ok: false, error: 'Address and payment method required' });
  }

  // Calculate total
  let total = 0;
  for (const item of items) {
    const price = Number(item.price);
    const qty = Number(item.qty);
    if (isNaN(price) || isNaN(qty) || qty < 1) {
      return res.status(400).json({ ok: false, error: 'Invalid item data' });
    }
    total += price * qty;
  }

  const orders = readJSON(ORDERS_FILE);
  const newOrder = {
    id: uuidv4(),
    userId: req.user.id,
    items,
    total,
    address,
    paymentMethod,
    createdAt: new Date().toISOString(),
    status: 'pending'
  };
  orders.push(newOrder);
  writeJSON(ORDERS_FILE, orders);

  res.status(201).json({ ok: true, orderId: newOrder.id });
});

// POST /api/contact
app.post('/api/contact', (req, res) => {
  let { name, email, message } = req.body;
  name = sanitizeString(name || '').trim();
  email = sanitizeString(email || '').toLowerCase().trim();
  message = sanitizeString(message || '').trim();

  if (!name || !email || !message) {
    return res.status(400).json({ ok: false, error: 'All fields are required' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ ok: false, error: 'Invalid email format' });
  }

  const logEntry = `[${new Date().toISOString()}] Contact from ${name} <${email}>: ${message}\n`;
  fs.appendFile(CONTACTS_LOG, logEntry, err => {
    if (err) {
      console.error('Failed to write contact log:', err);
    }
  });

  res.json({ ok: true });
});

// Optional sitemap.xml route
app.get('/sitemap.xml', (req, res) => {
  const baseUrl = `http://${req.headers.host}`;
  const pages = [
    '/dashboard/index.html',
    '/dashboard/menu.html',
    '/dashboard/about.html',
    '/dashboard/locations.html',
    '/dashboard/contact.html',
    '/dashboard/login.html',
    '/dashboard/register.html',
    '/dashboard/account.html',
    '/dashboard/cart.html',
    '/dashboard/checkout.html',
    '/dashboard/order-success.html',
    '/dashboard/privacy.html',
    '/dashboard/terms.html'
  ];
  const urls = pages.map(p => `
    <url>
      <loc>${baseUrl}${p}</loc>
      <changefreq>weekly</changefreq>
    </url>`).join('');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}
  </urlset>`;
  res.header('Content-Type', 'application/xml');
  res.send(xml);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
