const http = require("http");
const app = require("./server.js");

const server = app.listen(0, async () => {
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  async function post(path, body) {
    const r = await fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return r.json();
  }

  const goodWorkflow = {
    target: "preview",
    event: "pull_request",
    ref: "refs/heads/feature",
    workflow: {
      trigger: "pull_request",
      permissions: { contents: "read", packages: "write", "id-token": "none" },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: "actions", name: "checkout", ref: "v4" },
        { owner: "acme", name: "build", ref: "a".repeat(40) },
      ],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: "none",
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
  };

  let failures = 0;

  const r1 = await post("/release-gate", goodWorkflow);
  if (r1.decision !== "promote" || r1.violations.length !== 0) {
    console.error("FAIL: expected clean promote", r1);
    failures++;
  } else {
    console.log("PASS: release-gate promote case");
  }

  const badWorkflow = JSON.parse(JSON.stringify(goodWorkflow));
  badWorkflow.workflow.permissions["id-token"] = "write";
  const r2 = await post("/release-gate", badWorkflow);
  if (!r2.violations.includes("EXCESS_PERMISSION")) {
    console.error("FAIL: expected EXCESS_PERMISSION", r2);
    failures++;
  } else {
    console.log("PASS: release-gate excess permission case");
  }

  const r3 = await post("/action-firewall", {
    provenance: "untrusted",
    humanApproved: false,
    action: { tool: "search", args: { query: "hello" } },
  });
  if (r3.reason !== "ALLOW") {
    console.error("FAIL: expected ALLOW for search", r3);
    failures++;
  } else {
    console.log("PASS: action-firewall search allow");
  }

  const r4 = await post("/terraform/plan", {
    environment: "prod-ayw0c1",
    state: { backend: "gcs", locked: true },
    providerVersion: "~> 6.0",
    destroyApproved: false,
    resource: {
      address: "google_storage_bucket.data",
      type: "storage_bucket",
      action: "create",
      labels: { owner: "student-ukab4", environment: "production", cost_center: "cc-9lr1" },
      secret: null,
      forceDestroy: false,
    },
  });
  if (r4.decision !== "approve") {
    console.error("FAIL: expected approve", r4);
    failures++;
  } else {
    console.log("PASS: terraform plan approve");
  }

  server.close();

  if (failures > 0) {
    console.error(`${failures} test(s) failed`);
    process.exit(1);
  }
  console.log("All tests passed");
  process.exit(0);
});
