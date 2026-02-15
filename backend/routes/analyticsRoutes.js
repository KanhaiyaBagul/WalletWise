const express = require("express");
const router = express.Router();

const { protect } = require("../middleware/auth");
const { getAnalyticsSummary } = require("../controllers/analyticsController");

router.get("/summary", protect, getAnalyticsSummary);

module.exports = router;
