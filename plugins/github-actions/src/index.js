const core = require("@actions/core");
const github = require("@actions/github");
const axios = require("axios");
const fs = require("fs");
const { glob } = require("glob");
const path = require("path");

async function run() {
  const aceUrl = core.getInput("ace-url", { required: true });
  const environment = core.getInput("environment") || "production";
  const artifactsPath = core.getInput("artifacts-path") || "./k8s";
  const backendPath = core.getInput("backend-path") || "./src";
  const token = core.getInput("github-token") || process.env.GITHUB_TOKEN;
  const octokit = github.getOctokit(token);
  const ctx = github.context;

  const artifacts = discoverArtifacts(artifactsPath);
  core.info(`ACE: found ${artifacts.length} artifacts`);

  const backendSource = discoverBackendSource(backendPath);
  core.info(`ACE: found ${backendSource.length} backend source files (.env always excluded)`);

  let result;
  try {
    const resp = await axios.post(`${aceUrl}/rhg/submit`, {
      pipeline_id: ctx.runId.toString(),
      repo: `${ctx.repo.owner}/${ctx.repo.repo}`,
      branch: ctx.ref.replace("refs/heads/", ""),
      environment,
      artifacts,
      backend_source: backendSource,
    }, { timeout: 120000 });
    result = resp.data;
  } catch (err) {
    core.setFailed(`ACE gate request failed: ${err.message}`);
    return;
  }

  await core.summary
    .addHeading("ACE+RHG Compliance Gate")
    .addTable([
      ["Decision", "Mutations", "Compatibility", "OPS Notified"],
      [result.decision, result.mutations_applied.toString(),
       result.compatibility_verdict, result.ops_notified ? "Yes" : "No"],
    ])
    .addLink("Full report", result.report_url)
    .write();

  if (ctx.eventName === "pull_request") {
    try {
      await octokit.rest.issues.createComment({
        ...ctx.repo,
        issue_number: ctx.payload.pull_request.number,
        body: formatPRComment(result),
      });
    } catch (e) {
      core.warning(`Could not post PR comment: ${e.message}`);
    }
  }

  const state = result.decision === "BLOCK" ? "failure" : "success";
  await octokit.rest.repos.createCommitStatus({
    ...ctx.repo,
    sha: ctx.sha,
    state,
    target_url: result.report_url,
    description: `ACE gate: ${result.decision} — ${result.mutations_applied} auto-patches`,
    context: "ace-rhg/compliance-gate",
  });

  if (result.decision === "BLOCK") {
    core.setFailed(
      `ACE gate: BLOCK — ${result.blocking_findings.length} unresolvable violations. See ${result.report_url}`
    );
  } else {
    core.info(`ACE gate: ${result.decision}`);
  }
}

function discoverArtifacts(rootPath) {
  const found = [];
  const patterns = ["**/*.yaml", "**/*.yml", "**/*.tf", "**/*.tf.json", "**/Dockerfile", "**/*.dockerfile"];
  for (const pattern of patterns) {
    for (const file of glob.sync(pattern, { cwd: rootPath, ignore: excludeGlobs() })) {
      const full = path.join(rootPath, file);
      if (!fs.statSync(full).isFile()) continue;
      found.push({
        type: inferType(file),
        name: file,
        content: fs.readFileSync(full).toString("base64"),
      });
    }
  }
  return found;
}

function discoverBackendSource(rootPath) {
  const found = [];
  const ignore = [
    "**/.env", "**/.env.*", "**/.git/**", "**/node_modules/**",
    "**/__pycache__/**", "**/dist/**", "**/build/**", "**/*.min.js", "**/test/**", "**/tests/**",
  ];
  for (const pattern of ["**/*.py", "**/*.js", "**/*.ts", "**/*.go"]) {
    for (const file of glob.sync(pattern, { cwd: rootPath, ignore })) {
      const full = path.join(rootPath, file);
      if (!fs.statSync(full).isFile()) continue;
      found.push({
        language: inferLanguage(file),
        filename: file,
        content: fs.readFileSync(full).toString("base64"),
      });
    }
  }
  return found;
}

function excludeGlobs() {
  return ["**/.env", "**/.env.*", "**/.git/**", "**/node_modules/**"];
}

function inferType(filename) {
  if (filename.includes(".github/workflows")) return "github_actions";
  if (filename.endsWith(".tf") || filename.endsWith(".tf.json")) return "terraform";
  if (filename.includes("Dockerfile")) return "dockerfile";
  return "kubernetes";
}

function inferLanguage(filename) {
  if (filename.endsWith(".py")) return "python";
  if (filename.endsWith(".go")) return "go";
  return "node";
}

function formatPRComment(result) {
  const icon = { ALLOW: ":white_check_mark:", BLOCK: ":x:", PATCHED: ":wrench:" }[result.decision] || ":grey_question:";
  let comment = `## ${icon} ACE+RHG Compliance Gate: **${result.decision}**\n\n`;
  comment += `| Metric | Value |\n|---|---|\n`;
  comment += `| Auto-mutations applied | ${result.mutations_applied} |\n`;
  comment += `| Compatibility check | ${result.compatibility_verdict} |\n`;
  comment += `| OPS notified | ${result.ops_notified ? "Yes" : "No"} |\n\n`;
  if (result.blocking_findings && result.blocking_findings.length) {
    comment += "### Blocking violations\n";
    for (const f of result.blocking_findings) {
      comment += `- **[${f.severity}]** \`${f.rule_id}\` — ${f.message}\n`;
    }
    comment += "\n";
  }
  comment += `[View full report](${result.report_url})`;
  return comment;
}

run().catch(core.setFailed);