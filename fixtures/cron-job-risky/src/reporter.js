const cron = require("node-cron");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST });

// Scheduled report generator — runs every hour
// Risks: no overlap prevention, no timeout, no failure alert, no idempotency
cron.schedule("0 * * * *", async () => {
  const users = await pool.query("SELECT * FROM users WHERE active = true");

  for (const user of rows) {
    const report = await pool.query(
      "SELECT * FROM events WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'",
      [user.id]
    );

    // Send report email
    await transporter.sendMail({
      from: "reports@company.com",
      to: user.email,
      subject: "Hourly Report",
      html: generateReport(report.rows)
    });

    // Log completion — no idempotency check, could duplicate on re-run
    await pool.query(
      "INSERT INTO report_log (user_id, sent_at) VALUES ($1, NOW())",
      [user.id]
    );
  }
});

// Cleanup old logs — no timeout, could run indefinitely on large tables
cron.schedule("30 2 * * *", async () => {
  await pool.query("DELETE FROM report_log WHERE sent_at < NOW() - INTERVAL '90 days'");
});

function generateReport(events) {
  return `<h1>Report</h1><p>${events.length} events</p>`;
}
