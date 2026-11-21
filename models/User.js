const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
  id:        { type: String, required: true },
  name:      { type: String, required: true },
  status:    { type: String, default: 'online' },
  sub:       { type: String, default: 'New contact' },
  retention: { type: Number, default: 10 },
  note:      { type: String, default: '' },
  muted:     { type: Boolean, default: false }
}, { _id: false });

const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  companyId: { type: String, required: true, uppercase: true, trim: true },
  password:  { type: String, required: true },
  disabled:  { type: Boolean, default: false },
  bio:       { type: String, default: 'New to Whisper ✨' },
  avatarUrl: { type: String, default: '' },
  banner:    { type: String, default: '#0f766e' },
  settings: {
    theme:       { type: String, default: 'light' },
    accent:      { type: String, default: 'teal' },
    defaultLife: { type: Number, default: 10 },
    typing:      { type: Boolean, default: true },
    autoReply:   { type: Boolean, default: true },
    blur:        { type: Boolean, default: false },
    sound:       { type: Boolean, default: false }
  },
  contacts: [contactSchema]
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);