const express = require("express");
const app = express();
app.use(express.json());

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
const isStr = (v) => typeof v === "string";
const isBool = (v) => typeof v === "boolean";
const isPlainObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isInt = (v) => typeof v === "number" && Number.isInteger(v);

/* ==================================================================== */
/* 1) POST /release-gate                                                */
/* ==================================================================== */
app.post("/release-gate", (req, res) => {
  const violations = [];
  const b = req.body || {};

  try {
    const target = b.target;
    const event = b.event;
    const ref = b.ref;
    const wf = b.workflow || {};
    const perms = wf.permissions || {};
    const actions = Array.isArray(wf.actions) ? wf.actions : [];
    const img = b.image || {};

    // --- Permissions: exact least privilege ---
    const requiredPerms = { contents: "read", packages: "write", "id-token": "none" };
    const permKeys = Object.keys(perms);
    const permsOk =
      permKeys.length === 3 &&
      perms.contents === "read" &&
      perms.packages === "write" &&
      perms["id-token"] === "none";
    if (!permsOk) violations.push("EXCESS_PERMISSION");

    // --- PR safety ---
    const trigger = wf.trigger;
    const isPR = trigger === "pull_request" || trigger === "pull_request_target";
    if (trigger === "pull_request_target") {
      violations.push("UNSAFE_PR_TRIGGER");
    }
    if (isPR) {
      const testsOk =
        wf.testsPassed === true &&
        wf.matrixComplete === true &&
        wf.failFast === false;
      if (!testsOk) violations.push("TESTS_INCOMPLETE");
    }

    // --- Action pinning ---
    const shaRe = /^[0-9a-f]{40}$/;
    let mutable = false;
    for (const a of actions) {
      if (!a || !isStr(a.owner) || !isStr(a.name) || !isStr(a.ref)) {
        mutable = true;
        continue;
      }
      if (a.owner === "actions") {
        // version tag allowed, any non-empty string is fine
        continue;
      }
      if (!shaRe.test(a.ref)) mutable = true;
    }
    if (mutable) violations.push("MUTABLE_ACTION");

    // --- Image checks ---
    if (img.multiStage !== true) violations.push("SINGLE_STAGE_IMAGE");
    if (img.runsAsRoot !== false) violations.push("ROOT_RUNTIME");
    if (!(img.secretMode === "none" || img.secretMode === "buildkit")) {
      violations.push("SECRET_IN_LAYER");
    }
    if (!(img.criticalVulnerabilities === 0)) violations.push("CRITICAL_CVE");
    if (img.digestPinned !== true) violations.push("UNPINNED_IMAGE");

    // --- Production extra requirements ---
    if (target === "production") {
      if (!(event === "push" && ref === "refs/heads/main")) {
        violations.push("INVALID_PRODUCTION_REF");
      }
      if (wf.environmentApproval !== true) {
        violations.push("APPROVAL_REQUIRED");
      }
    }

    const decision = violations.length === 0 ? "promote" : "block";
    res.status(200).json({ decision, violations });
  } catch (e) {
    res.status(200).json({ decision: "block", violations: ["EXCESS_PERMISSION"] });
  }
});

/* ==================================================================== */
/* 2) POST /action-firewall                                             */
/* ==================================================================== */
const ASSIGNED_TENANT = "tenant-oaxpr3h";
const EMAIL_DOMAIN = "notify-3x7va9q.example";

function reply(res, reason) {
  return res.status(200).json({ decision: reason === "ALLOW" ? "allow" : "block", reason });
}

app.post("/action-firewall", (req, res) => {
  const b = req.body;

  // 1. top-level schema
  if (
    !isPlainObj(b) ||
    (b.provenance !== "trusted" && b.provenance !== "untrusted") ||
    !isBool(b.humanApproved) ||
    (b.untrustedContent !== undefined && !isStr(b.untrustedContent)) ||
    !isPlainObj(b.action) ||
    !isStr(b.action.tool) ||
    !isPlainObj(b.action.args)
  ) {
    return reply(res, "INVALID_SCHEMA");
  }

  const tool = b.action.tool;
  const args = b.action.args;
  const allowedTools = ["search", "lookup_record", "send_email", "render_html"];

  // 2. tool allowlist
  if (!allowedTools.includes(tool)) {
    return reply(res, "TOOL_NOT_ALLOWED");
  }

  // 3. argument schema (exact keys) per tool
  const keysMatch = (obj, expectedKeys) => {
    const k = Object.keys(obj);
    return k.length === expectedKeys.length && expectedKeys.every((x) => k.includes(x));
  };

  if (tool === "search") {
    if (
      !keysMatch(args, ["query"]) ||
      !isStr(args.query) ||
      args.query.length < 1 ||
      args.query.length > 200
    ) {
      return reply(res, "INVALID_SCHEMA");
    }
    return reply(res, "ALLOW");
  }

  if (tool === "lookup_record") {
    if (
      !keysMatch(args, ["tenantId", "recordId"]) ||
      !isStr(args.tenantId) ||
      !isStr(args.recordId) ||
      args.recordId.length < 1
    ) {
      return reply(res, "INVALID_SCHEMA");
    }
    // 4. tenant scope
    if (args.tenantId !== ASSIGNED_TENANT) {
      return reply(res, "TENANT_SCOPE");
    }
    return reply(res, "ALLOW");
  }

  if (tool === "send_email") {
    if (
      !keysMatch(args, ["to", "subject", "body"]) ||
      !isStr(args.to) ||
      !isStr(args.subject) ||
      !isStr(args.body)
    ) {
      return reply(res, "INVALID_SCHEMA");
    }
    // 5. exact email domain
    const at = args.to.lastIndexOf("@");
    const domain = at === -1 ? "" : args.to.slice(at + 1);
    if (domain !== EMAIL_DOMAIN) {
      return reply(res, "EGRESS_DENIED");
    }
    // 6. human approval
    if (b.humanApproved !== true) {
      return reply(res, "APPROVAL_REQUIRED");
    }
    return reply(res, "ALLOW");
  }

  if (tool === "render_html") {
    if (!keysMatch(args, ["html"]) || !isStr(args.html)) {
      return reply(res, "INVALID_SCHEMA");
    }
    // 7. HTML safety
    const html = args.html;
    const lower = html.toLowerCase();
    const unsafe =
      /<script[\s>]/.test(lower) ||
      /<\/script/.test(lower) ||
      /<iframe[\s>]/.test(lower) ||
      /\son[a-z]+\s*=/.test(lower) || // inline event handlers onclick= etc
      /javascript:/.test(lower);
    if (unsafe) {
      return reply(res, "UNSAFE_OUTPUT");
    }
    return reply(res, "ALLOW");
  }

  return reply(res, "TOOL_NOT_ALLOWED");
});

/* ==================================================================== */
/* 3) POST /terraform/plan                                              */
/* ==================================================================== */
const WORKSPACE = "prod-ayw0c1";
const REQUIRED_LABELS = {
  owner: "student-ukab4",
  environment: "production",
  cost_center: "cc-9lr1",
};

function tfReply(res, reason) {
  return res.status(200).json({ decision: reason === "APPROVE" ? "approve" : "reject", reason });
}

app.post("/terraform/plan", (req, res) => {
  const b = req.body;

  // 1. type validation
  const validShape =
    isPlainObj(b) &&
    isStr(b.environment) &&
    isPlainObj(b.state) &&
    isStr(b.state.backend) &&
    isBool(b.state.locked) &&
    isStr(b.providerVersion) &&
    isBool(b.destroyApproved) &&
    isPlainObj(b.resource) &&
    isStr(b.resource.address) &&
    isStr(b.resource.type) &&
    isStr(b.resource.action) &&
    ["create", "update", "delete"].includes(b.resource.action) &&
    isPlainObj(b.resource.labels) &&
    (b.resource.secret === null || isStr(b.resource.secret)) &&
    isBool(b.resource.forceDestroy);

  if (!validShape) return tfReply(res, "INVALID_PLAN");

  // 2. environment match
  if (b.environment !== WORKSPACE) return tfReply(res, "ENVIRONMENT_MISMATCH");

  // 3. state safety
  const validBackends = ["gcs", "s3", "azurerm", "remote"];
  if (!validBackends.includes(b.state.backend) || b.state.locked !== true) {
    return tfReply(res, "STATE_UNSAFE");
  }

  // 4. provider pinning
  const pv = b.providerVersion.trim();
  const exactRe = /^(=\s*)?6\.2\.1$/;
  const pessimisticRe = /^~>\s*6\.0$/;
  if (!(exactRe.test(pv) || pessimisticRe.test(pv))) {
    return tfReply(res, "UNPINNED_PROVIDER");
  }

  // 5. required labels
  const labels = b.resource.labels;
  const labelsOk = Object.entries(REQUIRED_LABELS).every(
    ([k, v]) => labels[k] === v
  );
  if (!labelsOk) return tfReply(res, "MISSING_LABELS");

  // 6. secret handling
  const secret = b.resource.secret;
  if (!(secret === null || (isStr(secret) && secret.startsWith("secret://") && secret.length > "secret://".length))) {
    return tfReply(res, "PLAINTEXT_SECRET");
  }

  // 7. destroy approval for stateful resources
  const statefulTypes = ["storage_bucket", "sql_database", "persistent_disk"];
  if (
    b.resource.action === "delete" &&
    statefulTypes.includes(b.resource.type) &&
    b.destroyApproved !== true
  ) {
    return tfReply(res, "DELETE_NOT_APPROVED");
  }

  // 8. force destroy on production storage bucket
  if (b.resource.type === "storage_bucket" && b.resource.forceDestroy === true) {
    return tfReply(res, "FORCE_DESTROY");
  }

  return tfReply(res, "APPROVE");
});

/* ==================================================================== */
app.get("/", (req, res) => res.send("TDS services running"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));

module.exports = app;
