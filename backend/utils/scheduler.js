const cron = require('node-cron');
const Subscription = require('../models/Subscription');
const { sendEmail } = require('./mailer');
const User = require('../models/User'); // Assuming you have a User model to get email

const checkUpcomingBills = async () => {
    console.log('⏳ Checking for upcoming bills...');
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const maxDaysLater = new Date(today);
        maxDaysLater.setDate(today.getDate() + 7);
        maxDaysLater.setHours(23, 59, 59, 999);

        // Find subscriptions due within exactly 7 days
        const upcomingSubscriptions = await Subscription.find({
            nextDueDate: {
                $gte: today,
                $lte: maxDaysLater
            },
            isActive: true
        }).populate('userId');

        console.log(`🔎 Found ${upcomingSubscriptions.length} active bills due within 7 days.`);

        for (const sub of upcomingSubscriptions) {
            if (!sub.userId || !sub.userId.email) {
                console.warn(`⚠️ Skipped subscription ${sub.name} (no user email)`);
                continue;
            }

            const prefs = sub.userId.notificationPrefs || { billRemindersEnabled: true, reminderDaysBefore: 3 };

            if (prefs.billRemindersEnabled === false) {
                continue;
            }

            const reminderDays = prefs.reminderDaysBefore || 3;

            const targetDateStart = new Date(today);
            targetDateStart.setDate(today.getDate() + reminderDays);
            targetDateStart.setHours(0, 0, 0, 0);

            const targetDateEnd = new Date(targetDateStart);
            targetDateEnd.setHours(23, 59, 59, 999);

            const dueDate = new Date(sub.nextDueDate);

            // Send email only if it's strictly within the exact target day interval
            if (dueDate >= targetDateStart && dueDate <= targetDateEnd) {
                const emailSubject = `Upcoming Bill: ${sub.name} is due soon!`;
                const emailHtml = `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #2563eb;">WalletWise Bill Reminder</h2>
                        <p>Hi ${sub.userId.fullName || sub.userId.email.split('@')[0] || 'there'},</p>
                        <p>This is a friendly reminder that your subscription for <strong>${sub.name}</strong> is due in ${reminderDays} day(s).</p>
                        
                        <div style="background-color: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0;">
                            <p style="margin: 5px 0;"><strong>Amount:</strong> ${sub.currency || '₹'}${sub.amount}</p>
                            <p style="margin: 5px 0;"><strong>Due Date:</strong> ${dueDate.toLocaleDateString()}</p>
                            <p style="margin: 5px 0;"><strong>Category:</strong> ${sub.category}</p>
                        </div>
    
                        <p>Make sure you have enough balance in your account!</p>
                        <p style="color: #6b7280; font-size: 12px; margin-top: 30px;">
                            You are receiving this email because you enabled bill tracking in WalletWise. You can update your notification preferences from your Profile Settings.
                        </p>
                    </div>
                `;

                await sendEmail({
                    to: sub.userId.email,
                    subject: emailSubject,
                    html: emailHtml
                });

                console.log(`✅ Email sent to ${sub.userId.email} for ${sub.name}`);
            }
        }

    } catch (error) {
        console.error('❌ Error in bill scheduler:', error);
    }
};

// Schedule the task to run every day at 9:00 AM
const initScheduler = () => {
    // Cron syntax: Second Minute Hour Day Month DayOfWeek
    // '0 9 * * *' = At 09:00 AM every day
    cron.schedule('0 9 * * *', () => {
        checkUpcomingBills();
    });

    console.log('📅 Scheduler initialized: Bill checks running daily at 9:00 AM.');
};

module.exports = { initScheduler, checkUpcomingBills }; // Export checkUpcomingBills for testing
