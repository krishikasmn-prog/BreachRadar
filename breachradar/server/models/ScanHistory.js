const mongoose = require('mongoose');

const scanHistorySchema = new mongoose.Schema({
  email: {
     type: String,
     required: true
     },
  scanDate: {
     type: Date,
      default: Date.now 
    },
  breachCount:
   { 
    type: Number,
     default: 0
     },
  riskScore:
   { 
    type: Number, 
    default: 0
   },
  breaches: [{
    name: String,
    domain: String,
    breachDate: String,
    dataClasses: [String],
    pwnCount: Number,
    logoPath: String
  }],
  severity:
   {
     type: String, 
     enum: ['Critical', 'High', 'Medium', 'Low', 'Safe'],
      default: 'Safe' }
});

scanHistorySchema.pre('save', function() {
  if (this.riskScore >= 80) this.severity = 'Critical';
  else if (this.riskScore >= 60) this.severity = 'High';
  else if (this.riskScore >= 40) this.severity = 'Medium';
  else if (this.riskScore > 0) this.severity = 'Low';
  else this.severity = 'Safe';
});

module.exports = mongoose.model('ScanHistory', scanHistorySchema);
