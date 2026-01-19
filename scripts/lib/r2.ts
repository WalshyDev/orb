import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { createHash } from "node:crypto";

export interface R2Config {
  accountId: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
}

export interface UploadOptions {
  sourcePath: string;
  destinationKey: string;
  contentType?: string;
}

export interface UploadResult {
  key: string;
  etag: string;
}

/**
 * Upload a file to R2 using the S3-compatible API.
 */
export async function uploadFile(
  config: R2Config,
  options: UploadOptions
): Promise<UploadResult> {
  const content = readFileSync(options.sourcePath);
  const contentMd5 = createHash("md5").update(content).digest("base64");

  const endpoint = `https://${config.accountId}.r2.cloudflarestorage.com`;
  const url = `${endpoint}/${config.bucket}/${options.destinationKey}`;
  const date = new Date().toUTCString();

  // Create AWS Signature v4
  const headers = await signRequest(config, {
    method: "PUT",
    url,
    headers: {
      "Content-Type": options.contentType ?? "application/octet-stream",
      "Content-MD5": contentMd5,
      "x-amz-date": date,
    },
    body: content,
  });

  const response = await fetch(url, {
    method: "PUT",
    headers,
    body: content,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`R2 upload failed: ${response.status} ${error}`);
  }

  const etag = response.headers.get("etag") ?? "";
  return { key: options.destinationKey, etag };
}

/**
 * Upload a directory to R2.
 */
export async function uploadDirectory(
  config: R2Config,
  sourceDir: string,
  destinationPrefix: string
): Promise<UploadResult[]> {
  const results: UploadResult[] = [];
  const files = readdirSync(sourceDir);

  for (const file of files) {
    const filePath = join(sourceDir, file);
    const stat = statSync(filePath);

    if (stat.isFile()) {
      const key = destinationPrefix ? `${destinationPrefix}/${file}` : file;
      console.error(`  Uploading ${file} -> ${key}`);

      const result = await uploadFile(config, {
        sourcePath: filePath,
        destinationKey: key,
      });
      results.push(result);
    }
  }

  return results;
}

// AWS Signature v4 implementation for R2
async function signRequest(
  config: R2Config,
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: Buffer;
  }
): Promise<Record<string, string>> {
  const url = new URL(request.url);
  const region = "auto";
  const service = "s3";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);

  const canonicalHeaders: Record<string, string> = {
    host: url.host,
    "x-amz-content-sha256": createHash("sha256")
      .update(request.body)
      .digest("hex"),
    "x-amz-date": amzDate,
    ...Object.fromEntries(
      Object.entries(request.headers).map(([k, v]) => [k.toLowerCase(), v])
    ),
  };

  const signedHeaderKeys = Object.keys(canonicalHeaders).sort();
  const signedHeaders = signedHeaderKeys.join(";");

  const canonicalHeadersStr = signedHeaderKeys
    .map((k) => `${k}:${canonicalHeaders[k]}`)
    .join("\n");

  const canonicalRequest = [
    request.method,
    url.pathname,
    url.search.slice(1),
    canonicalHeadersStr + "\n",
    signedHeaders,
    canonicalHeaders["x-amz-content-sha256"],
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");

  // Calculate signing key
  const kDate = hmacSha256(`AWS4${config.secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, "aws4_request");

  const signature = hmacSha256(kSigning, stringToSign).toString("hex");

  const authorization = `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    ...request.headers,
    host: url.host,
    "x-amz-content-sha256": canonicalHeaders["x-amz-content-sha256"]!,
    "x-amz-date": amzDate,
    Authorization: authorization,
  };
}

function hmacSha256(key: string | Buffer, data: string): Buffer {
  const { createHmac } = require("node:crypto");
  return createHmac("sha256", key).update(data).digest();
}
