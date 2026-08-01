let listing = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) {
  listing += chunk;
}

const files = listing
  .split(/\r?\n/u)
  .map((line) => line.trim().replaceAll("\\", "/"))
  .filter(Boolean);

if (!files.includes("dist/extension.js")) {
  throw new Error("VSIX package listing is missing dist/extension.js");
}

const requiredAgentSuite = [
  "chatmodes/forgewire-dispatcher.chatmode.md",
  "chatmodes/forgewire-runner.chatmode.md",
  "chatmodes/forgewire-approver.chatmode.md",
  "chatmodes/forgewire-observer.chatmode.md",
  "skills/dispatch-test-fix.prompt.md",
  "skills/dispatch-docs-sync.prompt.md",
  "skills/bisect-regression.prompt.md",
  "skills/triage-pending-approvals.prompt.md",
  "skills/replay-with-cheaper-model.prompt.md",
  "skills/enroll-runner.prompt.md",
  "skills/dispatch-cost-aware.prompt.md",
];
const missingAgentSuite = requiredAgentSuite.filter((file) => !files.includes(file));
if (missingAgentSuite.length > 0) {
  throw new Error(`VSIX package listing is missing agent-suite files: ${missingAgentSuite.join(", ")}`);
}

const forbidden = files.filter((file) =>
  file.startsWith("src/") ||
  file.startsWith("node_modules/") ||
  file.startsWith("scripts/") ||
  file.endsWith(".map") ||
  file.endsWith(".ts")
);
if (forbidden.length > 0) {
  throw new Error(`VSIX package listing contains development files: ${forbidden.join(", ")}`);
}

console.log(`verified VSIX package allowlist (${files.length} files)`);
