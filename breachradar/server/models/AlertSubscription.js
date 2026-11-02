const mongoose = require('mongoose');

const alertSubscriptionSchema = new mongoose.Schema({
  email:
   { 
    type: String,
    required: true, 
    unique: true 
  },
  subscribedAt:
   { 
    type: Date, 
    default: Date.now 
  },
  lastNotified: 
  { 
    type: Date

   },
  isActive:
   { 
    type: Boolean, 
    default: true
   }
});

module.exports = mongoose.model('AlertSubscription', alertSubscriptionSchema);
