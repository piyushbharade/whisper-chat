const mongoose = require('mongoose');

const policySchema = new mongoose.Schema({
  key:           { type: String, default: 'global', unique: true },
  allowSignup:   { type: Boolean, default: true },
  allowUploads:  { type: Boolean, default: true },
  allowViewOnce: { type: Boolean, default: true },
  maxMB:         { type: Number, default: 10 },
  audit: [{
    t:    { type: Number, default: Date.now },
    by:   String,
    text: String
  }]
});

module.exports = mongoose.model('Policy', policySchema);