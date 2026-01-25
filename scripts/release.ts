#!/usr/bin/env npx tsx
/**
 * Release orchestration script for orb.
 *
 * Commands:
 *   create-release <tag>     Create GitHub release with changelog
 *   upload-asset <tag> <path> <name>  Upload asset to release
 *   upload-r2 <source-dir> <dest-prefix>  Upload directory to R2
 *   finalize <version>       Generate manifest and upload to R2
 *
 * Environment variables:
 *   GITHUB_TOKEN        GitHub API token
 *   GITHUB_REPOSITORY   Repository in "owner/repo" format
 *   R2_ACCOUNT_ID       Cloudflare R2 account ID
 *   R2_ACCESS_KEY_ID    R2 access key
 *   R2_SECRET_ACCESS_KEY R2 secret key
 *   R2_BUCKET           R2 bucket name (default: "orb")
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { generateChangelog, generateReleaseBody } from "./lib/changelog.js";
import {
  createRelease,
  getReleaseByTag,
  uploadReleaseAsset,
  type GitHubConfig,
} from "./lib/github.js";
import { uploadDirectory, uploadFile, type R2Config } from "./lib/r2.js";

const PLATFORMS: Record<string, { downloadName: string }> = {
  "x86_64-apple-darwin": { downloadName: "orb-macos" },
  "aarch64-apple-darwin": { downloadName: "orb-macos" },
  "x86_64-unknown-linux-gnu": { downloadName: "orb-linux" },
  "x86_64-unknown-linux-musl": { downloadName: "orb-linux" },
  "x86_64-pc-windows-msvc": { downloadName: "orb-windows.exe" },
};

// All unique downloads that must be present for a complete release
const REQUIRED_DOWNLOADS = ["orb-linux", "orb-macos", "orb-windows.exe"];

function getGitHubConfig(): GitHubConfig {
  const token = process.env.GITHUB_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;

  if (!token) {
    console.error("Error: GITHUB_TOKEN environment variable is required");
    process.exit(1);
  }
  if (!repository) {
    console.error("Error: GITHUB_REPOSITORY environment variable is required");
    process.exit(1);
  }

  return { token, repository };
}

function getR2Config(): R2Config {
  const accountId = process.env.R2_ACCOUNT_ID;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  const bucket = process.env.R2_BUCKET ?? "orb";

  if (!accountId || !accessKeyId || !secretAccessKey) {
    console.error("Error: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, and R2_SECRET_ACCESS_KEY are required");
    process.exit(1);
  }

  return { accountId, accessKeyId, secretAccessKey, bucket };
}

async function cmdCreateRelease(tag: string): Promise<void> {
  console.error(`Creating release for ${tag}...`);

  const config = getGitHubConfig();
  const version = tag.replace(/^v/, "");

  // Check if release already exists
  const existing = await getReleaseByTag(config, tag);
  if (existing) {
    console.error(`Release ${tag} already exists: ${existing.htmlUrl}`);
    // Output for GitHub Actions
    console.log(`release_id=${existing.id}`);
    console.log(`upload_url=${existing.uploadUrl}`);
    return;
  }

  // Generate changelog
  console.error("Generating changelog...");
  const { changelog, previousTag } = generateChangelog(tag);

  // Generate release body
  const body = generateReleaseBody({
    changelog,
    previousTag,
    repository: config.repository,
    currentTag: tag,
  });

  // Create release
  console.error("Creating GitHub release...");
  const release = await createRelease(config, {
    tagName: tag,
    name: `orb ${tag}`,
    body,
    draft: false,
    prerelease: false,
  });

  console.error(`Release created: ${release.htmlUrl}`);

  // Output for GitHub Actions
  console.log(`release_id=${release.id}`);
  console.log(`upload_url=${release.uploadUrl}`);
}

async function cmdUploadAsset(tag: string, assetPath: string, assetName: string): Promise<void> {
  console.error(`Uploading ${assetName} to release ${tag}...`);

  const config = getGitHubConfig();

  const release = await getReleaseByTag(config, tag);
  if (!release) {
    console.error(`Error: Release ${tag} not found`);
    process.exit(1);
  }

  const asset = await uploadReleaseAsset(config, release, assetPath, assetName);
  console.error(`Uploaded: ${asset.browserDownloadUrl}`);
}

async function cmdUploadR2(sourceDir: string, destPrefix: string): Promise<void> {
  console.error(`Uploading ${sourceDir} to R2 ${destPrefix}/...`);

  const config = getR2Config();
  const results = await uploadDirectory(config, sourceDir, destPrefix);

  console.error(`Uploaded ${results.length} files to R2`);
  for (const result of results) {
    console.error(`  ${result.key}`);
  }
}

async function cmdFinalize(version: string): Promise<void> {
  console.error(`Finalizing release ${version}...`);

  const r2Config = getR2Config();
  const baseUrl = "https://orb-tools.com/downloads";

  // Generate manifest by fetching binaries from R2
  console.error("Generating update manifest...");

  interface BinaryInfo {
    url: string;
    sha256: string;
  }

  const manifest: {
    version: string;
    urgent: boolean;
    binaries: Record<string, BinaryInfo>;
  } = {
    version,
    urgent: false,
    binaries: {},
  };

  // Fetch each binary and compute hash
  const processedDownloads = new Set<string>();

  for (const [target, platform] of Object.entries(PLATFORMS)) {
    if (processedDownloads.has(platform.downloadName)) {
      // Same binary for multiple targets (e.g., both macOS archs use orb-macos)
      const existing = Object.values(manifest.binaries).find(
        (b) => b.url === `${baseUrl}/${platform.downloadName}`
      );
      if (existing) {
        manifest.binaries[target] = existing;
        console.error(`  ${target}: reusing ${platform.downloadName}`);
        continue;
      }
    }

    const downloadUrl = `${baseUrl}/${platform.downloadName}`;
    console.error(`  Fetching ${platform.downloadName}...`);
    try {
      const response = await fetch(downloadUrl, {
        headers: { "User-Agent": "orb-release-script" },
      });

      if (!response.ok) {
        console.error(`    Failed: HTTP ${response.status} from ${downloadUrl}`);
        continue;
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      const sha256 = createHash("sha256").update(buffer).digest("hex");

      manifest.binaries[target] = {
        url: downloadUrl,
        sha256,
      };

      processedDownloads.add(platform.downloadName);
      console.error(`    SHA256: ${sha256.slice(0, 16)}... (${buffer.length} bytes)`);
    } catch (error) {
      console.error(`    Skipping: ${error instanceof Error ? error.message : error}`);
    }
  }

  if (Object.keys(manifest.binaries).length === 0) {
    console.error("Error: No platforms were successfully processed!");
    process.exit(1);
  }

  // Verify all required downloads are present
  const missingDownloads = REQUIRED_DOWNLOADS.filter(
    (name) => !processedDownloads.has(name)
  );
  if (missingDownloads.length > 0) {
    console.error(`Error: Missing required binaries: ${missingDownloads.join(", ")}`);
    console.error("All platform binaries must be available for a complete release.");
    process.exit(1);
  }

  // Write manifest locally
  const manifestJson = JSON.stringify(manifest, null, 2);
  const manifestDir = join(process.cwd(), "r2-manifest");
  mkdirSync(manifestDir, { recursive: true });
  writeFileSync(join(manifestDir, "manifest.json"), manifestJson);

  console.error("\nGenerated manifest:");
  console.error(manifestJson);

  // Upload to R2
  console.error("\nUploading manifest to R2...");
  await uploadFile(r2Config, {
    sourcePath: join(manifestDir, "manifest.json"),
    destinationKey: "update/manifest.json",
    contentType: "application/json",
  });

  console.error(`\nSuccessfully processed ${Object.keys(manifest.binaries).length} platforms`);
}

function printUsage(): void {
  console.error(`Usage: npx tsx release.ts <command> [args]

Commands:
  create-release <tag>                Create GitHub release with changelog
  upload-asset <tag> <path> <name>    Upload asset to release
  upload-r2 <source-dir> <dest>       Upload directory to R2
  finalize <version>                  Generate manifest and upload to R2

Environment variables:
  GITHUB_TOKEN          GitHub API token
  GITHUB_REPOSITORY     Repository in "owner/repo" format
  R2_ACCOUNT_ID         Cloudflare R2 account ID
  R2_ACCESS_KEY_ID      R2 access key
  R2_SECRET_ACCESS_KEY  R2 secret key
  R2_BUCKET             R2 bucket name (default: "orb")
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    printUsage();
    process.exit(command ? 0 : 1);
  }

  switch (command) {
    case "create-release": {
      const tag = args[1];
      if (!tag) {
        console.error("Error: tag is required");
        process.exit(1);
      }
      await cmdCreateRelease(tag);
      break;
    }

    case "upload-asset": {
      const [, tag, assetPath, assetName] = args;
      if (!tag || !assetPath || !assetName) {
        console.error("Error: tag, path, and name are required");
        process.exit(1);
      }
      await cmdUploadAsset(tag, assetPath, assetName);
      break;
    }

    case "upload-r2": {
      const [, sourceDir, destPrefix] = args;
      if (!sourceDir || !destPrefix) {
        console.error("Error: source-dir and dest-prefix are required");
        process.exit(1);
      }
      await cmdUploadR2(sourceDir, destPrefix);
      break;
    }

    case "finalize": {
      const version = args[1];
      if (!version) {
        console.error("Error: version is required");
        process.exit(1);
      }
      await cmdFinalize(version);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

main().catch((error) => {
  console.error("Error:", error);
  process.exit(1);
});
