#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const desktopRoot = resolve(scriptDir, "../..");

const PLATFORM_ALIASES = new Map([
  ["win32", "windows"],
  ["windows", "windows"],
  ["darwin", "macos"],
  ["macos", "macos"],
  ["linux", "linux"],
]);

const TOOL_PROBES = {
  node: ["node", ["--version"]],
  npm: ["npm", ["--version"]],
  cargo: ["cargo", ["--version"]],
  rustc: ["rustc", ["--version"]],
  pwsh: ["pwsh", ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"]],
  signtool: ["signtool", ["/?"]],
  "pkg-config": ["pkg-config", ["--version"]],
  cc: ["cc", ["--version"]],
  "dpkg-deb": ["dpkg-deb", ["--version"]],
  rpmbuild: ["rpmbuild", ["--version"]],
  hdiutil: ["hdiutil", ["help"]],
  xcrun: ["xcrun", ["--version"]],
  codesign: ["codesign", ["--version"]],
  security: ["security", ["help"]],
};

const COMMON_SIGNING_ENV = [
  "TAURI_SIGNING_PRIVATE_KEY",
  "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
  "FORGEWIRE_UPDATER_PUBLIC_KEY",
];

const PLATFORM_SIGNING_ENV = {
  windows: ["FORGEWIRE_WINDOWS_CERT_THUMBPRINT", "FORGEWIRE_WINDOWS_TIMESTAMP_URL"],
  macos: [
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_SIGNING_IDENTITY",
    "APPLE_ID",
    "APPLE_PASSWORD",
    "APPLE_TEAM_ID",
  ],
  linux: [],
};

function usage(message) {
  if (message) process.stderr.write(`${message}\n\n`);
  process.stderr.write(
    "Usage: desktop-release.mjs <plan|preflight|build> [--platform windows|macos|linux] " +
      "[--mode development|release] [--arch ARCH] [--evidence PATH] [--tool-manifest PATH] " +
      "[--environment-manifest PATH] [--dry-run]\n",
  );
  process.exit(message ? 64 : 0);
}

function parseArgs(argv) {
  if (argv.length === 0 || argv.includes("--help")) usage();
  const operation = argv[0];
  if (!["plan", "preflight", "build"].includes(operation)) usage(`Unknown operation: ${operation}`);
  const options = {
    operation,
    platform: PLATFORM_ALIASES.get(process.platform),
    arch: process.arch,
    mode: operation === "build" ? "release" : "development",
    evidence: resolve(desktopRoot, "dist-release/release-evidence.json"),
    toolManifest: null,
    environmentManifest: null,
    dryRun: false,
    platformOverride: false,
  };
  for (let index = 1; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--dry-run") {
      options.dryRun = true;
      continue;
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) usage(`Missing value for ${flag}`);
    index += 1;
    if (flag === "--platform") {
      options.platform = PLATFORM_ALIASES.get(value);
      options.platformOverride = true;
    }
    else if (flag === "--arch") options.arch = value;
    else if (flag === "--mode") options.mode = value;
    else if (flag === "--evidence") options.evidence = resolve(value);
    else if (flag === "--tool-manifest") options.toolManifest = resolve(value);
    else if (flag === "--environment-manifest") options.environmentManifest = resolve(value);
    else usage(`Unknown option: ${flag}`);
  }
  if (!options.platform) usage("Unsupported platform");
  if (!["development", "release"].includes(options.mode)) usage(`Unsupported mode: ${options.mode}`);
  return options;
}

function loadJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`Unable to read ${label} ${path}: ${error.message}`);
  }
}

function manifestTool(manifest, name) {
  const entry = manifest[name];
  if (typeof entry === "string") return { found: true, version: entry, source: "manifest" };
  if (entry && typeof entry === "object") {
    return {
      found: entry.found !== false,
      version: entry.version ? String(entry.version) : null,
      source: "manifest",
    };
  }
  return { found: false, version: null, source: "manifest" };
}

function spawnHost(command, args, options) {
  if (process.platform === "win32" && command === "npm") {
    // npm's Windows entry point is a command shim. These arguments are all
    // internal enum/static values, so cmd.exe can invoke the shim directly.
    const commandLine = ["npm.cmd", ...args].join(" ");
    return spawnSync(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", commandLine], options);
  }
  return spawnSync(command, args, options);
}

function probeTool(name, manifest) {
  if (manifest) return manifestTool(manifest, name);
  const [command, args] = TOOL_PROBES[name];
  const result = spawnHost(command, args, { encoding: "utf8", windowsHide: true });
  if (result.error || result.status !== 0) return { found: false, version: null, source: "path" };
  const output = `${result.stdout || ""}\n${result.stderr || ""}`
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean);
  return { found: true, version: output || "available", source: "path" };
}

function requiredToolNames(platform) {
  if (platform === "windows") return ["node", "npm", "cargo", "rustc", "pwsh", "signtool"];
  if (platform === "macos") return ["node", "npm", "cargo", "rustc", "hdiutil", "xcrun", "codesign", "security"];
  return ["node", "npm", "cargo", "rustc", "pkg-config", "cc", "dpkg-deb", "rpmbuild"];
}

function readEnvironmentReadiness(options) {
  const names = [...COMMON_SIGNING_ENV, ...PLATFORM_SIGNING_ENV[options.platform]];
  const manifest = options.environmentManifest ? loadJson(options.environmentManifest, "environment manifest") : null;
  return Object.fromEntries(
    names.map((name) => {
      const ready = manifest
        ? manifest[name] === true || manifest[name]?.present === true
        : typeof process.env[name] === "string" && process.env[name].trim().length > 0;
      return [name, { present: ready }];
    }),
  );
}

function signingToolNames(platform) {
  if (platform === "windows") return ["signtool"];
  if (platform === "macos") return ["xcrun", "codesign", "security"];
  return [];
}

function makeTarget(name, format, selected, toolNames, tools) {
  const missing = toolNames.filter((tool) => !tools[tool]?.found);
  return {
    name,
    format,
    selected,
    ready: selected && missing.length === 0,
    requiredTools: toolNames,
    blockedReasons: missing.map((tool) => `required tool not found: ${tool}`),
  };
}

function planTargets(platform, tools) {
  const base = ["node", "npm", "cargo", "rustc"];
  if (platform === "windows") {
    return [
      makeTarget("nsis", "native", true, base, tools),
      makeTarget("msi", "native", true, base, tools),
      makeTarget("zip", "legacy-portable", true, [...base, "pwsh"], tools),
    ];
  }
  if (platform === "macos") {
    return [
      makeTarget("app", "native", true, [...base, "codesign"], tools),
      makeTarget("dmg", "native", true, [...base, "hdiutil"], tools),
    ];
  }
  return [
    makeTarget("appimage", "native", true, [...base, "pkg-config", "cc"], tools),
    makeTarget("deb", "native", tools["dpkg-deb"].found, [...base, "pkg-config", "cc", "dpkg-deb"], tools),
    makeTarget("rpm", "native", tools.rpmbuild.found, [...base, "pkg-config", "cc", "rpmbuild"], tools),
  ];
}

function compareVersions(left, right) {
  const leftParts = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const rightParts = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const delta = (leftParts[index] || 0) - (rightParts[index] || 0);
    if (delta !== 0) return delta;
  }
  return 0;
}

function dependencySecurity(options) {
  if (options.platform !== "linux") {
    return { checked: false, ready: true, advisories: [] };
  }

  const lockPath = resolve(desktopRoot, "src-tauri/Cargo.lock");
  const lock = readFileSync(lockPath, "utf8");
  const match = lock.match(/\[\[package\]\]\s+name = "glib"\s+version = "([^"]+)"/m);
  const version = match?.[1] || null;
  const vulnerable = !version || compareVersions(version, "0.20.0") < 0;
  return {
    checked: true,
    ready: !vulnerable,
    advisories: vulnerable
      ? [
          {
            id: "GHSA-wrw7-89jp-8q8g",
            package: "glib",
            detectedVersion: version,
            patchedVersion: ">=0.20.0",
            status: version ? "upstream-blocked" : "unverified",
          },
        ]
      : [],
  };
}

function commandPlan(platform, targets) {
  const native = targets.filter((target) => target.selected && target.format === "native").map((target) => target.name);
  const commands = [];
  if (native.length > 0) {
    commands.push({
      id: "tauri-native-bundles",
      command: "npm",
      args: ["run", "tauri", "--", "build", "--bundles", native.join(",")],
      cwd: desktopRoot,
    });
  }
  if (platform === "windows") {
    commands.push({
      id: "windows-portable-zip",
      command: "pwsh",
      args: [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        resolve(desktopRoot, "package/windows/package-forgewire-fabric-desktop.ps1"),
        "-SkipBuild",
      ],
      cwd: desktopRoot,
    });
  }
  return commands;
}

function collectEvidence(options) {
  const toolManifest = options.toolManifest ? loadJson(options.toolManifest, "tool manifest") : null;
  const tools = Object.fromEntries(
    requiredToolNames(options.platform).map((name) => [name, probeTool(name, toolManifest)]),
  );
  const signingEnvironment = readEnvironmentReadiness(options);
  const signingTools = signingToolNames(options.platform);
  const targets = planTargets(options.platform, tools);
  const security = dependencySecurity(options);
  const blockedReasons = [];

  for (const target of targets.filter((item) => item.selected)) blockedReasons.push(...target.blockedReasons);
  if (targets.every((target) => !target.selected)) blockedReasons.push("no supported bundle target is available");

  if (options.mode === "release") {
    for (const [name, state] of Object.entries(signingEnvironment)) {
      if (!state.present) blockedReasons.push(`required release metadata is absent: ${name}`);
    }
    for (const name of signingTools) {
      if (!tools[name].found) blockedReasons.push(`required release signing tool not found: ${name}`);
    }
    for (const advisory of security.advisories) {
      blockedReasons.push(
        `release dependency advisory unresolved: ${advisory.id} (${advisory.package} ${advisory.detectedVersion || "unknown"}; patched ${advisory.patchedVersion})`,
      );
    }
  }

  const uniqueBlockedReasons = [...new Set(blockedReasons)];
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    operation: options.operation,
    evidenceKind: options.toolManifest || options.environmentManifest ? "manifest-plan" : "host-probe",
    hostPlatform: PLATFORM_ALIASES.get(process.platform),
    platform: options.platform,
    platformSource: options.platformOverride ? "override" : "host",
    architecture: options.arch,
    mode: options.mode,
    dryRun: options.dryRun,
    status: uniqueBlockedReasons.length === 0 ? "ready" : "blocked",
    targets,
    tools,
    signing: {
      required: options.mode === "release",
      environment: signingEnvironment,
      requiredTools: signingTools,
      toolsReady: signingTools.every((name) => tools[name]?.found),
      ready:
        Object.values(signingEnvironment).every((state) => state.present) &&
        signingTools.every((name) => tools[name]?.found),
    },
    security,
    commands: commandPlan(options.platform, targets).map((command) => ({ ...command, status: "planned" })),
    blockedReasons: uniqueBlockedReasons,
  };
}

function writeEvidence(path, evidence) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  if (existsSync(path)) rmSync(path);
  renameSync(temporary, path);
}

function executeBuild(evidence) {
  for (const command of evidence.commands) {
    const result = spawnHost(command.command, command.args, {
      cwd: command.cwd,
      encoding: "utf8",
      stdio: "inherit",
      windowsHide: true,
    });
    command.status = result.status === 0 ? "passed" : "failed";
    command.exitCode = result.status;
    if (result.status !== 0) {
      evidence.status = "failed";
      evidence.blockedReasons.push(`build command failed: ${command.id}`);
      return false;
    }
  }
  evidence.status = "built";
  return true;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const evidence = collectEvidence(options);
  writeEvidence(options.evidence, evidence);

  if (options.operation === "plan") {
    process.stdout.write(`${options.evidence}\n`);
    return;
  }
  if (evidence.status === "blocked") {
    process.stderr.write(`Desktop release lane blocked; see ${options.evidence}\n`);
    process.exitCode = 2;
    return;
  }
  if (options.operation === "preflight" || options.dryRun) {
    process.stdout.write(`${options.evidence}\n`);
    return;
  }
  const success = executeBuild(evidence);
  writeEvidence(options.evidence, evidence);
  if (!success) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
