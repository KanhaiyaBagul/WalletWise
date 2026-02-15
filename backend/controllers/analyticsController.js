const mongoose = require("mongoose");
const Transaction = require("../models/Transactions");

exports.getAnalyticsSummary = async (req, res) => {
  try {
    const userObjectId = new mongoose.Types.ObjectId(req.userId);

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const categoryTotals = await Transaction.aggregate([
      {
        $match: {
          userId: userObjectId,
          type: "expense",
          date: { $gte: startOfMonth }
        }
      },
      {
        $group: {
          _id: "$category",
          total: { $sum: "$amount" }
        }
      }
    ]);

    const formatted = categoryTotals.map(c => ({
      category: c._id,
      total: c.total
    }));

// 6 Month Trend

const sixMonthsAgo = new Date();
sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 5);

const monthlyTrends = await Transaction.aggregate([
  {
    $match: {
      userId: userObjectId,
      type: "expense",
      date: { $gte: sixMonthsAgo }
    }
  },
  {
    $group: {
      _id: {
        year: { $year: "$date" },
        month: { $month: "$date" }
      },
      total: { $sum: "$amount" }
    }
  },
  {
    $sort: { "_id.year": 1, "_id.month": 1 }
  }
]);

const formattedTrends = monthlyTrends.map(t => ({
  year: t._id.year,
  month: t._id.month,
  total: t.total
}));

// Sort trends by year then month (oldest → newest)
formattedTrends.sort((a, b) => {
  if (a.year !== b.year) return a.year - b.year;
  return a.month - b.month;
});


// Fetch last 6 months transactions for recurring detection

const recentTransactions = await Transaction.find({
  userId: userObjectId,
  type: "expense",
  date: { $gte: sixMonthsAgo }
}).sort({ date: 1 });

const recurringMap = {};

recentTransactions.forEach(tx => {
  const key = tx.description?.toLowerCase().trim();
  if (!key) return;

  if (!recurringMap[key]) {
    recurringMap[key] = [];
  }

  recurringMap[key].push(tx);
});

const recurring = [];

for (const [desc, transactions] of Object.entries(recurringMap)) {

  if (transactions.length < 3) continue; // at least 3 occurrences

  const amounts = transactions.map(t => t.amount);
  const firstAmount = amounts[0];

  const similarAmounts = amounts.every(a =>
    Math.abs(a - firstAmount) <= firstAmount * 0.1
  );

  if (!similarAmounts) continue;

  recurring.push({
    description: desc,
    averageAmount: Math.round(
      amounts.reduce((a, b) => a + b, 0) / amounts.length
    ),
    occurrences: transactions.length
  });
}

// Last 3 months average per category

const threeMonthsAgo = new Date(startOfMonth);
threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);

const last3MonthsData = await Transaction.aggregate([
  {
    $match: {
      userId: userObjectId,
      type: "expense",
      date: {
        $gte: threeMonthsAgo,
        $lt: startOfMonth  
      }
    }
  },
  {
    $group: {
      _id: "$category",
      average: { $avg: "$amount" }
    }
  }
]);


const anomalies = [];

formatted.forEach(currentCategory => {
  const avgData = last3MonthsData.find(
    item => item._id === currentCategory.category
  );

  if (!avgData) return;

  const average = avgData.average;

  if (currentCategory.total > average * 1.5) {
    anomalies.push({
      category: currentCategory.category,
      currentTotal: currentCategory.total,
      averageLast3Months: Math.round(average),
      threshold: Math.round(average * 1.5)
    });
  }
});

// Sort recurring by highest frequency
recurring.sort((a, b) => b.occurrences - a.occurrences);


    res.json({
  categoryTotals: formatted,
  trends: formattedTrends,
  recurring,
  anomalies
});


  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Analytics error" });
  }
};
