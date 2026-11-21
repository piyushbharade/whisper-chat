require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Server } = require('socket.io');

const User = require('./models/User');
const Admin = require('./models/Admin');
const Policy = require('./models/Policy');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, 'uploads/'),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

const getRoomId = (u1, u2) => [u1.toLowerCase(), u2.toLowerCase()].sort().join('__');

/* --- JWT AUTHENTICATION MIDDLEWARE --- */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication token required.' });
  try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!['whisper_admin', 'company_admin'].includes(req.auth.role)) {
      return res.status(403).json({ error: 'Admin privileges required.' });
    }
    next();
  });
}

function requireWhisperAdmin(req, res, next) {
  requireAdmin(req, res, () => {
    if (req.auth.role !== 'whisper_admin') {
      return res.status(403).json({ error: 'Only a Whisper Super Admin can perform this action.' });
    }
    next();
  });
}

/* --- SEED DEFAULT ACCOUNTS --- */
async function seedDefaults() {
  if (!(await Policy.findOne({ key: 'global' }))) {
    await Policy.create({ key: 'global' });
  }
  if (!(await User.findOne({ username: 'rasmalai' }))) {
    await User.create({
      username: 'rasmalai',
      name: 'Rasmalai',
      email: 'rasmalai@example.com',
      companyId: 'WH-1001',
      password: await bcrypt.hash('supersecret', 10),
      bio: 'Software engineer · keeping conversations light and ephemeral ✨',
      contacts: []
    });
  }
  // 1. Whisper Super Admin (Master Company ID: WHISPER-HQ)
  if (!(await Admin.findOne({ username: 'admin' }))) {
    await Admin.create({
      username: 'admin',
      name: 'Whisper Admin',
      email: 'admin@whisper.app',
      adminId: 'ADM-1001',
      companyId: 'WHISPER-HQ',
      role: 'whisper_admin',
      password: await bcrypt.hash('admin@123', 10)
    });
  } else {
    // Ensure existing 'admin' is upgraded to whisper_admin with WHISPER-HQ
    await Admin.updateOne(
      { username: 'admin', companyId: { $exists: false } },
      { $set: { companyId: 'WHISPER-HQ', role: 'whisper_admin' } }
    );
  }
  // 2. Sample Company Admin for WH-1001
  if (!(await Admin.findOne({ username: 'compadmin' }))) {
    await Admin.create({
      username: 'compadmin',
      name: 'WH-1001 Manager',
      email: 'manager@wh1001.com',
      adminId: 'ADM-2001',
      companyId: 'WH-1001',
      role: 'company_admin',
      password: await bcrypt.hash('company@123', 10)
    });
  }
}

/* --- EMPLOYEE AUTH & TEAMMATE DISCOVERY --- */
app.post('/api/auth/register', async (req, res) => {
  try {
    const policy = await Policy.findOne({ key: 'global' });
    if (!policy.allowSignup) return res.status(403).json({ error: 'Sign-ups are turned off by your company admin.' });
    const { name, username, email, companyId, password } = req.body;
    const uname = username.trim().toLowerCase().replace(/\s+/g, '_');
    const cid = companyId.trim().toUpperCase();
    if (cid === 'WHISPER-HQ') return res.status(400).json({ error: 'WHISPER-HQ is reserved for platform administrators.' });

    const exists = await User.findOne({ $or: [{ username: uname }, { email: email.toLowerCase() }] });
    if (exists) return res.status(400).json({ error: 'Username or email already exists.' });

    const user = await User.create({
      username: uname,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      companyId: cid,
      password: await bcrypt.hash(password, 10),
      contacts: []
    });

    const teammates = await User.find({ companyId: cid, username: { $ne: uname }, disabled: false })
      .select('username name bio').lean();

    const token = jwt.sign({ id: user._id, username: user.username, companyId: cid, role: 'employee' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user, teammates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { id, password, companyId } = req.body;
    const k = id.trim().toLowerCase();
    const cid = companyId.trim().toUpperCase();
    const user = await User.findOne({ $or: [{ username: k }, { email: k }] });
    if (!user || !(await bcrypt.compare(password, user.password)) || user.companyId !== cid) {
      return res.status(401).json({ error: 'Username, password or company ID is incorrect.' });
    }
    if (user.disabled) return res.status(403).json({ error: 'This account is suspended. Contact your company admin.' });

    const teammates = await User.find({ companyId: cid, username: { $ne: user.username }, disabled: false })
      .select('username name bio').lean();

    const token = jwt.sign({ id: user._id, username: user.username, companyId: cid, role: 'employee' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user, teammates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:username/sync', requireAuth, async (req, res) => {
  try {
    if (req.auth.username !== req.params.username.toLowerCase()) {
      return res.status(403).json({ error: 'Cannot sync another user profile.' });
    }
    const { name, bio, avatarUrl, banner, settings, contacts } = req.body;
    const user = await User.findOneAndUpdate(
      { username: req.params.username.toLowerCase() },
      { $set: { name, bio, avatarUrl, banner, settings, contacts } },
      { new: true }
    );
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:username', requireAuth, async (req, res) => {
  if (req.auth.username !== req.params.username.toLowerCase()) {
    return res.status(403).json({ error: 'Cannot delete another user account.' });
  }
  await User.deleteOne({ username: req.params.username.toLowerCase() });
  res.json({ ok: true });
});

/* --- MESSAGES, UPLOADS & CROSS-BROWSER VANISH --- */
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  const policy = await Policy.findOne({ key: 'global' });
  if (!policy.allowUploads) return res.status(403).json({ error: 'Uploads disabled by admin.' });
  if (!req.file) return res.status(400).json({ error: 'No file provided.' });
  res.json({
    url: `/uploads/${req.file.filename}`,
    name: req.file.originalname,
    size: req.file.size,
    kind: req.file.mimetype.startsWith('image/') ? 'image' : 'file'
  });
});

app.get('/api/messages/:u1/:u2', requireAuth, async (req, res) => {
  const roomId = getRoomId(req.params.u1, req.params.u2);
  const msgs = await Message.find({
    roomId,
    $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }]
  }).sort({ createdAt: 1 });
  res.json(msgs);
});

app.delete('/api/messages/:id/view-once', requireAuth, async (req, res) => {
  const msg = await Message.findByIdAndDelete(req.params.id);
  if (msg?.attach?.url) fs.unlink(path.join(__dirname, msg.attach.url), () => {});
  if (msg) io.to(msg.roomId).emit('message_vanished', { id: msg._id });
  res.json({ ok: true });
});

// Wipe a specific 1-on-1 chat across both browsers & MongoDB
app.delete('/api/messages/room/:u1/:u2', requireAuth, async (req, res) => {
  const u1 = req.params.u1.toLowerCase();
  const u2 = req.params.u2.toLowerCase();
  if (req.auth.username !== u1 && req.auth.username !== u2) {
    return res.status(403).json({ error: 'Not authorized for this room.' });
  }
  const roomId = getRoomId(u1, u2);
  const msgs = await Message.find({ roomId });
  msgs.forEach(m => {
    if (m.attach?.url) fs.unlink(path.join(__dirname, m.attach.url), () => {});
  });
  await Message.deleteMany({ roomId });
  io.to(u1).to(u2).to(roomId).emit('chat_vanished', { scope: 'room', u1, u2 });
  res.json({ ok: true });
});

// Wipe ALL conversations for a user across all connected browsers & MongoDB
app.delete('/api/messages/user/:username', requireAuth, async (req, res) => {
  const uname = req.params.username.toLowerCase();
  if (req.auth.username !== uname) {
    return res.status(403).json({ error: 'Cannot wipe another user’s messages.' });
  }
  const msgs = await Message.find({ $or: [{ sender: uname }, { recipient: uname }] });
  const peers = new Set();
  msgs.forEach(m => {
    if (m.attach?.url) fs.unlink(path.join(__dirname, m.attach.url), () => {});
    peers.add(m.sender === uname ? m.recipient : m.sender);
  });
  await Message.deleteMany({ $or: [{ sender: uname }, { recipient: uname }] });
  peers.forEach(peer => {
    io.to(peer).emit('chat_vanished', { scope: 'room', u1: uname, u2: peer });
  });
  io.to(uname).emit('chat_vanished', { scope: 'all', user: uname });
  res.json({ ok: true });
});

/* --- TWO-TIER ADMIN & POLICY ROUTES --- */
app.get('/api/policy', async (_, res) => res.json(await Policy.findOne({ key: 'global' })));

app.post('/api/admin/login', async (req, res) => {
  const { username, adminId, companyId, password } = req.body;
  const k = username.trim().toLowerCase();
  const aid = adminId.trim().toUpperCase();
  const cid = companyId.trim().toUpperCase();

  const admin = await Admin.findOne({ $or: [{ username: k }, { email: k }] });
  if (!admin || admin.adminId !== aid || admin.companyId !== cid || !(await bcrypt.compare(password, admin.password))) {
    return res.status(401).json({ error: 'Username, admin ID, company ID, or password is incorrect.' });
  }
  const role = cid === 'WHISPER-HQ' ? 'whisper_admin' : 'company_admin';
  const token = jwt.sign(
    { id: admin._id, username: admin.username, companyId: admin.companyId, role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, admin: { ...admin.toObject(), role } });
});

// Only an existing Whisper Super Admin can create new Whisper Admins or Company Admins
app.post('/api/admin/create-admin', requireWhisperAdmin, async (req, res) => {
  try {
    const { name, username, email, adminId, companyId, password } = req.body;
    const uname = username.trim().toLowerCase().replace(/\s+/g, '_');
    const aid = adminId.trim().toUpperCase();
    const cid = companyId.trim().toUpperCase();
    const role = cid === 'WHISPER-HQ' ? 'whisper_admin' : 'company_admin';

    const exists = await Admin.findOne({ $or: [{ username: uname }, { email: email.toLowerCase() }, { adminId: aid }] });
    if (exists) return res.status(400).json({ error: 'Admin username, email, or Admin ID already exists.' });

    const admin = await Admin.create({
      username: uname,
      name: (name || uname).trim(),
      email: email.trim().toLowerCase(),
      adminId: aid,
      companyId: cid,
      role,
      password: await bcrypt.hash(password, 10)
    });

    await Policy.updateOne({ key: 'global' }, {
      $push: { audit: { $each: [{ t: Date.now(), by: req.auth.username, text: `created ${role === 'whisper_admin' ? 'Whisper Admin' : `Company Admin (${cid})`} @${uname}` }], $position: 0, $slice: 40 } }
    });
    res.status(201).json({ admin });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/admins/:username', requireWhisperAdmin, async (req, res) => {
  const target = req.params.username.toLowerCase();
  if (target === req.auth.username) return res.status(400).json({ error: 'You cannot remove your own admin account.' });
  await Admin.deleteOne({ username: target });
  await Policy.updateOne({ key: 'global' }, {
    $push: { audit: { $each: [{ t: Date.now(), by: req.auth.username, text: `removed admin @${target}` }], $position: 0, $slice: 40 } }
  });
  res.json({ ok: true });
});

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  const isSuper = req.auth.role === 'whisper_admin';
  const empFilter = isSuper ? {} : { companyId: req.auth.companyId };
  const adminFilter = isSuper ? {} : { companyId: req.auth.companyId };

  const [employees, admins, policy] = await Promise.all([
    User.find(empFilter).select('-password').lean(),
    Admin.find(adminFilter).select('-password').lean(),
    Policy.findOne({ key: 'global' }).lean()
  ]);
  res.json({ employees, admins, policy, role: req.auth.role, companyId: req.auth.companyId });
});

app.post('/api/admin/employees', requireAdmin, async (req, res) => {
  try {
    const { name, username, email, companyId, password, by } = req.body;
    const uname = username.trim().toLowerCase().replace(/\s+/g, '_');
    // Company Admins can ONLY add employees to their own companyId
    const targetCid = req.auth.role === 'whisper_admin' ? companyId.trim().toUpperCase() : req.auth.companyId;
    if (targetCid === 'WHISPER-HQ') return res.status(400).json({ error: 'Cannot add employees under WHISPER-HQ.' });

    const user = await User.create({
      username: uname,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      companyId: targetCid,
      password: await bcrypt.hash(password, 10)
    });
    await Policy.updateOne({ key: 'global' }, { $push: { audit: { $each: [{ t: Date.now(), by, text: `added employee ${name} (@${uname}) to ${targetCid}` }], $position: 0, $slice: 40 } } });
    res.status(201).json({ user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/admin/employees/:username', requireAdmin, async (req, res) => {
  const targetUser = await User.findOne({ username: req.params.username.toLowerCase() });
  if (!targetUser) return res.status(404).json({ error: 'Employee not found.' });
  if (req.auth.role !== 'whisper_admin' && targetUser.companyId !== req.auth.companyId) {
    return res.status(403).json({ error: 'You can only manage employees in your own company.' });
  }

  const { name, email, companyId, disabled, newPassword, by, auditText } = req.body;
  const update = {};
  if (name !== undefined) update.name = name;
  if (email !== undefined) update.email = email.toLowerCase();
  if (companyId !== undefined && req.auth.role === 'whisper_admin') update.companyId = companyId.toUpperCase();
  if (disabled !== undefined) update.disabled = disabled;
  if (newPassword) update.password = await bcrypt.hash(newPassword, 10);

  await User.updateOne({ username: targetUser.username }, { $set: update });
  if (auditText) {
    await Policy.updateOne({ key: 'global' }, { $push: { audit: { $each: [{ t: Date.now(), by, text: auditText }], $position: 0, $slice: 40 } } });
  }
  res.json({ ok: true });
});

app.delete('/api/admin/employees/:username', requireAdmin, async (req, res) => {
  const targetUser = await User.findOne({ username: req.params.username.toLowerCase() });
  if (!targetUser) return res.status(404).json({ error: 'Employee not found.' });
  if (req.auth.role !== 'whisper_admin' && targetUser.companyId !== req.auth.companyId) {
    return res.status(403).json({ error: 'You can only remove employees in your own company.' });
  }

  await User.deleteOne({ username: targetUser.username });
  await Policy.updateOne({ key: 'global' }, { $push: { audit: { $each: [{ t: Date.now(), by: req.query.by || 'Admin', text: `removed @${targetUser.username}` }], $position: 0, $slice: 40 } } });
  res.json({ ok: true });
});

app.patch('/api/admin/password', requireAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const admin = await Admin.findOne({ username: req.auth.username });
    if (!admin || !(await bcrypt.compare(currentPassword, admin.password))) {
      return res.status(401).json({ error: 'Your current password is incorrect.' });
    }
    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();
    await Policy.updateOne({ key: 'global' }, {
      $push: { audit: { $each: [{ t: Date.now(), by: admin.name, text: 'changed their own password' }], $position: 0, $slice: 40 } }
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/policy', requireWhisperAdmin, async (req, res) => {
  const { key, value, by, label } = req.body;
  await Policy.updateOne(
    { key: 'global' },
    {
      $set: { [key]: value },
      $push: { audit: { $each: [{ t: Date.now(), by, text: label }], $position: 0, $slice: 40 } }
    }
  );
  io.emit('policy_updated', await Policy.findOne({ key: 'global' }));
  res.json({ ok: true });
});

/* --- REAL-TIME SOCKET.IO --- */
io.on('connection', (socket) => {
  socket.on('register_user', (username) => {
    if (username) socket.join(username.toLowerCase());
  });

  socket.on('join_chat', ({ me, peer }) => {
    if (me) socket.join(me.toLowerCase());
    if (me && peer) socket.join(getRoomId(me, peer));
  });

  socket.on('send_message', async ({ sender, recipient, text, life, attach }) => {
    const s = sender.toLowerCase();
    const r = recipient.toLowerCase();
    const roomId = getRoomId(s, r);
    const ttl = Number(life) || 0;
    const expiresAt = ttl > 0 ? new Date(Date.now() + ttl * 1000) : null;

    const saved = await Message.create({
      roomId, sender: s, recipient: r, text, life: ttl, expiresAt, attach: attach || null
    });

    io.to(r).to(s).to(roomId).emit('receive_message', saved);
  });
});

app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index_admin_id.html')));

mongoose.connect(process.env.MONGO_URI).then(async () => {
  await seedDefaults();
  server.listen(process.env.PORT, () => console.log(`Whisper running at http://localhost:${process.env.PORT}`));
});