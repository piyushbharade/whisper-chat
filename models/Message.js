const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  roomId:    { type: String, required: true, index: true },
  sender:    { type: String, required: true },
  recipient: { type: String, required: true },
  text:      { type: String, default: '' },
  life:      { type: Number, default: 10 },
  expiresAt: { type: Date, default: null },
  attach: {
    kind: { type: String },
    url:  { type: String },
    name: { type: String },
    size: { type: Number },
    once: { type: Boolean, default: false }
  }
}, { timestamps: true });

messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Message', messageSchema);