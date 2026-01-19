import { execSync } from "node:child_process";

export interface ChangelogResult {
  changelog: string;
  previousTag: string | null;
}

/**
 * Generate changelog from git history between tags.
 */
export function generateChangelog(currentTag: string): ChangelogResult {
  // Get previous tag
  let previousTag: string | null = null;
  try {
    previousTag = execSync("git describe --tags --abbrev=0 HEAD^", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    // No previous tag exists
    previousTag = null;
  }

  // Generate commit log
  let changelog: string;
  if (previousTag) {
    changelog = execSync(
      `git log ${previousTag}..${currentTag} --pretty=format:"- %s (%h)" --no-merges`,
      { encoding: "utf-8" }
    ).trim();
  } else {
    changelog = execSync(
      `git log ${currentTag} --pretty=format:"- %s (%h)" --no-merges`,
      { encoding: "utf-8" }
    ).trim();
  }

  return { changelog, previousTag };
}

export interface ReleaseBodyOptions {
  changelog: string;
  previousTag: string | null;
  repository: string;
  currentTag: string;
  baseUrl?: string;
}

/**
 * Generate the release body markdown.
 */
export function generateReleaseBody(options: ReleaseBodyOptions): string {
  const {
    changelog,
    previousTag,
    repository,
    currentTag,
    baseUrl = "https://orb-tools.com/downloads",
  } = options;

  const lines: string[] = [
    "## What's Changed",
    "",
    changelog,
    "",
    "## Installation",
    "",
    "### Quick Download",
    "",
    "| Platform | Download |",
    "|----------|----------|",
    `| macOS (Universal) | [orb-macos](${baseUrl}/orb-macos) |`,
    `| Linux (x64) | [orb-linux](${baseUrl}/orb-linux) |`,
    `| Windows (x64) | [orb-windows.exe](${baseUrl}/orb-windows.exe) |`,
    "",
    "Or download with orb/curl:",
    "",
    "### Install with orb/curl",
    "",
    "```bash",
    "# macOS",
    `orb -L ${baseUrl}/orb-macos -o orb && chmod +x orb`,
    `curl -L ${baseUrl}/orb-macos -o orb && chmod +x orb`,
    "",
    "# Linux",
    `orb -L ${baseUrl}/orb-linux -o orb && chmod +x orb`,
    `curl -L ${baseUrl}/orb-linux -o orb && chmod +x orb`,
    "```",
    "",
    "[Full Documentation](https://orb-tools.com)",
    "",
  ];

  if (previousTag) {
    lines.push(
      `**Full Changelog**: https://github.com/${repository}/compare/${previousTag}...${currentTag}`
    );
  } else {
    lines.push(`**Commits**: https://github.com/${repository}/commits/${currentTag}`);
  }

  return lines.join("\n");
}
