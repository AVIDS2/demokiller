// Hardened AWS Lambda handler — production-quality serverless security controls.
"use strict";

const { DynamoDBClient, PutItemCommand, GetItemCommand } = require("@aws-sdk/client-dynamodb");
const crypto = require("node:crypto");

// ─── Connection pool outside handler (reused across warm invocations) ──

const dynamoClient = new DynamoDBClient({
  region: process.env.AWS_REGION || "us-east-1",
  maxAttempts: 3,
  requestTimeout: 5000,
});

const TABLE_NAME = process.env.DYNAMO_TABLE || "events";
const DLQ_URL = process.env.DLQ_URL || "";
const MAX_RETRIES = 3;
const IDEMPOTENCY_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

// ─── Input validation ──────────────────────────────────────────────

function validateEvent(body) {
  const errors = [];
  if (!body || typeof body !== "object") {
    errors.push("Request body must be a JSON object");
    return { valid: false, errors };
  }
  if (!body.action || typeof body.action !== "string" || body.action.length > 100) {
    errors.push("action is required and must be a string (max 100 chars)");
  }
  if (body.payload && typeof body.payload !== "object") {
    errors.push("payload must be an object if provided");
  }
  if (body.callbackUrl) {
    try {
      const url = new URL(body.callbackUrl);
      if (!["https:"].includes(url.protocol)) {
        errors.push("callbackUrl must use HTTPS");
      }
    } catch {
      errors.push("callbackUrl must be a valid URL");
    }
  }
  return { valid: errors.length === 0, errors };
}

// ─── Idempotency check via DynamoDB ────────────────────────────────

async function isDuplicate(eventId) {
  try {
    const result = await dynamoClient.send(new GetItemCommand({
      TableName: TABLE_NAME,
      Key: { eventId: { S: eventId } },
      ProjectionExpression: "eventId",
    }));
    return !!result.Item;
  } catch (err) {
    // If we can't check idempotency, log and allow (prefer processing over dropping)
    console.warn(JSON.stringify({
      level: "warn",
      msg: "idempotency_check_failed",
      eventId,
      error: err.message,
    }));
    return false;
  }
}

async function recordProcessed(eventId, action) {
  const ttl = Math.floor((Date.now() + IDEMPOTENCY_WINDOW_MS) / 1000);
  await dynamoClient.send(new PutItemCommand({
    TableName: TABLE_NAME,
    Item: {
      eventId: { S: eventId },
      action: { S: action },
      processedAt: { S: new Date().toISOString() },
      ttl: { N: String(ttl) },
    },
  }));
}

// ─── DLQ pattern for failed events ─────────────────────────────────

async function sendToDLQ(originalEvent, error, retryCount) {
  if (!DLQ_URL) {
    console.error(JSON.stringify({
      level: "error",
      msg: "dlq_not_configured",
      eventId: originalEvent.eventId,
      error: error.message,
    }));
    return;
  }

  // In production this would use SQS SendMessage; log the intent for the fixture
  console.error(JSON.stringify({
    level: "error",
    msg: "sent_to_dlq",
    eventId: originalEvent.eventId,
    action: originalEvent.body?.action,
    retryCount,
    error: error.message,
    dlqUrl: DLQ_URL,
  }));
}

// ─── Business logic (sandboxed from handler I/O concerns) ──────────

async function processAction(action, payload) {
  // Stub: in production this dispatches to domain logic
  switch (action) {
    case "order.created":
      return { status: "confirmed", orderId: crypto.randomUUID() };
    case "user.registered":
      return { status: "welcomed", userId: payload?.userId || "unknown" };
    default:
      return { status: "acknowledged" };
  }
}

// ─── Main Lambda handler ───────────────────────────────────────────

exports.handler = async (event, context) => {
  // Lambda context: set timeout warning at 80% of allocated time
  const timeoutMs = context.getRemainingTimeInMillis ? context.getRemainingTimeInMillis() : 30000;
  const timeoutWarning = setTimeout(() => {
    console.warn(JSON.stringify({
      level: "warn",
      msg: "lambda_timeout_approaching",
      remainingMs: timeoutMs,
      requestId: context.awsRequestId,
    }));
  }, timeoutMs * 0.8);

  try {
    // Parse and validate input
    let body;
    try {
      body = typeof event.body === "string" ? JSON.parse(event.body) : event.body;
    } catch {
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Invalid JSON in request body" }),
      };
    }

    const validation = validateEvent(body);
    if (!validation.valid) {
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Validation failed", details: validation.errors }),
      };
    }

    // Idempotency: use provided eventId or generate deterministic one
    const eventId = event.headers?.["x-idempotency-key"]
      || body.idempotencyKey
      || crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");

    if (await isDuplicate(eventId)) {
      console.info(JSON.stringify({
        level: "info",
        msg: "duplicate_event_skipped",
        eventId,
        requestId: context.awsRequestId,
      }));
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "duplicate", eventId }),
      };
    }

    // Process with retry budget
    let result;
    let lastError;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        result = await processAction(body.action, body.payload);
        break;
      } catch (err) {
        lastError = err;
        console.warn(JSON.stringify({
          level: "warn",
          msg: "action_retry",
          attempt,
          action: body.action,
          error: err.message,
          requestId: context.awsRequestId,
        }));
        if (attempt < MAX_RETRIES) {
          await new Promise((r) => setTimeout(r, Math.pow(2, attempt) * 100));
        }
      }
    }

    if (!result && lastError) {
      await sendToDLQ({ eventId, body }, lastError, MAX_RETRIES);
      return {
        statusCode: 500,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: "Processing failed after retries" }),
      };
    }

    // Record successful processing (idempotency marker)
    await recordProcessed(eventId, body.action);

    console.info(JSON.stringify({
      level: "info",
      msg: "event_processed",
      eventId,
      action: body.action,
      requestId: context.awsRequestId,
    }));

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "ok", eventId, result }),
    };
  } catch (err) {
    // Generic error handler — no stack traces to client
    console.error(JSON.stringify({
      level: "error",
      msg: "unhandled_error",
      error: err.message,
      requestId: context.awsRequestId,
    }));
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Internal server error" }),
    };
  } finally {
    clearTimeout(timeoutWarning);
  }
};
