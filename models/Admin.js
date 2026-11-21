const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, lowercase: true, trim: true },
  name:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  adminId:   { type: String, required: true, unique: true, uppercase: true, trim: true },
  companyId: { type: String, required: true, uppercase: true, trim: true }, // 'WHISPER-HQ' for Whisper Super Admin, or company ID like 'WH-1001'
  role:      { type: String, enum: ['whisper_admin', 'company_admin'], default: 'company_admin' },
  password:  { type: String, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Admin', adminSchema);