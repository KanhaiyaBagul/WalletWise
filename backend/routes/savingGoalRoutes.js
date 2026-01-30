const express = require('express');
const router = express.Router();
const SavingsGoal = require('../models/SavingsGoal');
const verifyToken = require('../middleware/auth'); // Make sure you have this

// Create Savings Goal
router.post('/', verifyToken, async (req, res) => {
  try {
    const {
      name,
      description,
      targetAmount,
      currentAmount = 0,
      targetDate,
      category = 'Other',
      priority = 'Medium',
      monthlyContribution = 0,
      isActive = true
    } = req.body;

    // Validation
    if (!name || !name.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Goal name is required'
      });
    }

    if (!targetAmount || targetAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Target amount must be greater than 0'
      });
    }

    if (!targetDate) {
      return res.status(400).json({
        success: false,
        message: 'Target date is required'
      });
    }

    const targetDateObj = new Date(targetDate);
    if (targetDateObj <= new Date()) {
      return res.status(400).json({
        success: false,
        message: 'Target date must be in the future'
      });
    }

    const savingsGoal = new SavingsGoal({
      userId: req.userId,
      name: name.trim(),
      description: description?.trim() || `Saving for ${name.trim()}`,
      targetAmount: parseFloat(targetAmount),
      currentAmount: parseFloat(currentAmount),
      targetDate: targetDateObj,
      category,
      priority,
      monthlyContribution: parseFloat(monthlyContribution),
      isActive
    });

    await savingsGoal.save();

    res.status(201).json({
      success: true,
      message: 'Savings goal created successfully',
      goal: savingsGoal
    });

  } catch (error) {
    console.error('Create savings goal error:', error);
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: messages.join(', ')
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Error creating savings goal'
    });
  }
});

// Get all savings goals
router.get('/', verifyToken, async (req, res) => {
  try {
    const savingsGoals = await SavingsGoal.find({ userId: req.userId, isActive: true })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      goals: savingsGoals
    });

  } catch (error) {
    console.error('Get savings goals error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching savings goals' 
    });
  }
});

module.exports = router;
module.exports = router;