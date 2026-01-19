import { readFileSync } from "node:fs";

const GITHUB_API = "https://api.github.com";

export interface GitHubConfig {
  token: string;
  repository: string; // "owner/repo"
}

export interface ReleaseOptions {
  tagName: string;
  name: string;
  body: string;
  draft?: boolean;
  prerelease?: boolean;
}

export interface Release {
  id: number;
  uploadUrl: string;
  htmlUrl: string;
}

export interface UploadedAsset {
  name: string;
  browserDownloadUrl: string;
}

async function githubFetch(
  config: GitHubConfig,
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const url = path.startsWith("http") ? path : `${GITHUB_API}${path}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${config.token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...options.headers,
    },
  });

  return response;
}

/**
 * Create a GitHub release.
 */
export async function createRelease(
  config: GitHubConfig,
  options: ReleaseOptions
): Promise<Release> {
  const response = await githubFetch(
    config,
    `/repos/${config.repository}/releases`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tag_name: options.tagName,
        name: options.name,
        body: options.body,
        draft: options.draft ?? false,
        prerelease: options.prerelease ?? false,
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to create release: ${response.status} ${error}`);
  }

  const data = await response.json();
  return {
    id: data.id,
    uploadUrl: data.upload_url,
    htmlUrl: data.html_url,
  };
}

/**
 * Get an existing release by tag name.
 */
export async function getReleaseByTag(
  config: GitHubConfig,
  tagName: string
): Promise<Release | null> {
  const response = await githubFetch(
    config,
    `/repos/${config.repository}/releases/tags/${tagName}`
  );

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get release: ${response.status} ${error}`);
  }

  const data = await response.json();
  return {
    id: data.id,
    uploadUrl: data.upload_url,
    htmlUrl: data.html_url,
  };
}

/**
 * Upload an asset to a release.
 */
export async function uploadReleaseAsset(
  config: GitHubConfig,
  release: Release,
  assetPath: string,
  assetName: string
): Promise<UploadedAsset> {
  const content = readFileSync(assetPath);

  // The upload_url has a template like: https://uploads.github.com/.../assets{?name,label}
  const uploadUrl = release.uploadUrl
    .replace("{?name,label}", "")
    .replace("{?name}", "");

  const response = await fetch(`${uploadUrl}?name=${encodeURIComponent(assetName)}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/octet-stream",
      "Content-Length": content.length.toString(),
    },
    body: content,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to upload asset: ${response.status} ${error}`);
  }

  const data = await response.json();
  return {
    name: data.name,
    browserDownloadUrl: data.browser_download_url,
  };
}

/**
 * Get release assets.
 */
export async function getReleaseAssets(
  config: GitHubConfig,
  releaseId: number
): Promise<UploadedAsset[]> {
  const response = await githubFetch(
    config,
    `/repos/${config.repository}/releases/${releaseId}/assets`
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get assets: ${response.status} ${error}`);
  }

  const data = await response.json();
  return data.map((asset: { name: string; browser_download_url: string }) => ({
    name: asset.name,
    browserDownloadUrl: asset.browser_download_url,
  }));
}
