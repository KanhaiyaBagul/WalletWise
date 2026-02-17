module.exports = async ({ github, context }) => {
  const owner = context.repo.owner;
  const repo = context.repo.repo;

  const SLA = {
    "difficulty: easy": 2,
    "difficulty: medium": 4,
    "difficulty: hard": 7,
  };

  const now = new Date();
  const dayStamp = now.toISOString().slice(0, 10);
  const dailyMarker = `<!-- daily-difficulty-reminder:${dayStamp} -->`;

  const msPerDay = 24 * 60 * 60 * 1000;

  const addDaysUTC = (dateObj, days) => {
    const d = new Date(dateObj);
    d.setUTCDate(d.getUTCDate() + days);
    return d;
  };

  const isoDate = (d) => d.toISOString().slice(0, 10);

  const issues = await github.paginate(github.rest.issues.listForRepo, {
    owner,
    repo,
    state: "open",
    per_page: 100,
  });

  for (const issue of issues) {
    if (issue.pull_request) continue;

    const labels = (issue.labels || []).map((l) =>
      typeof l === "string" ? l : l.name
    );
    const diffLabel = Object.keys(SLA).find((l) => labels.includes(l));
    if (!diffLabel) continue;

    const assignees = (issue.assignees || []).map((a) => a.login);
    if (assignees.length === 0) continue;

    const slaDays = SLA[diffLabel];

    const events = await github.paginate(github.rest.issues.listEvents, {
      owner,
      repo,
      issue_number: issue.number,
      per_page: 100,
    });

    const assignedEvents = events
      .filter((e) => e.event === "assigned" && e.created_at)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const assignedAt = assignedEvents.length
      ? new Date(assignedEvents[0].created_at)
      : new Date(issue.created_at);

    const dueAt = addDaysUTC(assignedAt, slaDays);

    const daysLeft = Math.ceil((dueAt - now) / msPerDay);
    const assignedDateStr = isoDate(assignedAt);
    const dueDateStr = isoDate(dueAt);

    const comments = await github.paginate(github.rest.issues.listComments, {
      owner,
      repo,
      issue_number: issue.number,
      per_page: 100,
    });

    if (comments.some((c) => (c.body || "").includes(dailyMarker))) continue;

    const mentions = assignees.map((u) => `@${u}`).join(" ");

    let statusLine;
    let actionLine;

    if (daysLeft > 0) {
      statusLine = `✅ **${daysLeft} day(s) left** (due on **${dueDateStr}**)`;
      actionLine = `Please share a quick update (progress + blockers).`;
    } else if (daysLeft === 0) {
      statusLine = `⚠️ **Due today** (**${dueDateStr}**)`;
      actionLine = `Please finish today or comment blockers.`;
    } else {
      statusLine = `🚨 **Overdue by ${Math.abs(daysLeft)} day(s)** (was due on **${dueDateStr}**)`;
      actionLine = `Please complete **ASAP**. If there’s no progress update soon, this may be **reassigned** to someone else.`;
    }

    const body = `${dailyMarker}
⏰ **Daily Reminder** (${diffLabel})

- Assigned on: **${assignedDateStr}**
- SLA: **${slaDays} days**
- ${statusLine}

${mentions}
${actionLine}
`;

    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: issue.number,
      body,
    });
  }
};
