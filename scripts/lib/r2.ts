import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

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

function createS3Client(config: R2Config): S3Client {
  return new S3Client({
    region: "auto",
    endpoint: `https://${config.accountId}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
  });
}

/**
 * Upload a file to R2 using the S3-compatible API.
 */
export async function uploadFile(
  config: R2Config,
  options: UploadOptions
): Promise<UploadResult> {
  const client = createS3Client(config);
  const content = readFileSync(options.sourcePath);

  const command = new PutObjectCommand({
    Bucket: config.bucket,
    Key: options.destinationKey,
    Body: content,
    ContentType: options.contentType ?? "application/octet-stream",
  });

  const response = await client.send(command);
  const etag = response.ETag ?? "";

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
