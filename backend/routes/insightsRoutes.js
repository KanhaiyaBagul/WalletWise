const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const {
  getAnomalies,
  getSubscriptionAlerts,
  getSeasonal,
  getWeekendWeekday,
  getInsightsSummary,
  evaluatePurchase
} = require('../controllers/insightsController');

router.use(protect);

router.get('/anomalies', getAnomalies);
router.get('/subscriptions/alerts', getSubscriptionAlerts);
router.get('/seasonal', getSeasonal);
router.get('/weekend-weekday', getWeekendWeekday);
router.get('/summary', getInsightsSummary);
router.post('/evaluate', evaluatePurchase);

module.exports = router;

