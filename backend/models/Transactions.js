// models/Transaction.js
const mongoose = require('mongoose');
const { CATEGORIES } = require('../constants/categories');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['expense', 'income'],
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  category: {
    type: String,
    enum: CATEGORIES,
    required: true
  },
  description: {
    type: String,
    trim: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'card', 'upi', 'online'],
    default: 'cash'
  },
  mood: {
    type: String,
    enum: ['happy', 'stressed', 'bored', 'sad', 'calm', 'neutral'],
    default: 'neutral'
  }
}, { timestamps: true });

// Indexes for analytics performance
transactionSchema.index({ userId: 1, type: 1, date: -1 });
transactionSchema.index({ userId: 1, category: 1 });
transactionSchema.index({ userId: 1, description: 1 });

module.exports = mongoose.model('Transaction', transactionSchema);