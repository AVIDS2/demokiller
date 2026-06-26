const { Pool } = require("pg");
const { S3Client, GetObjectCommand } = require("@aws-sdk/client-s3");

// Global connection pool — created on cold start, reused on warm start
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const s3 = new S3Client({});

// Lambda handler for S3 event notifications
// Risks: no cold start handling, no timeout, no concurrency limit, no idempotency
exports.handler = async (event) => {
  for (const record of event.Records) {
    const bucket = record.s3.bucket.name;
    const key = record.s3.object.key;

    // Download file from S3
    const response = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    const body = await response.Body.transformToString();
    const data = JSON.parse(body);

    // Process each item — DB write without idempotency
    for (const item of data.items) {
      await pool.query(
        "INSERT INTO events (type, payload, created_at) VALUES ($1, $2, NOW())",
        [item.type, JSON.stringify(item)]
      );
    }

    // No timeout protection — if S3 or DB hangs, Lambda runs until AWS kills it (15min max)
    // No concurrency limit — burst of S3 events spawns many concurrent Lambdas
  }

  return { statusCode: 200, body: "OK" };
};
