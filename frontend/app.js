(() => {
  "use strict";

  const CONFIGS_URL = "/experiments/configurations";
  const EXPERIMENTS_URL = "/experiments";
  const HEALTH_URL = "/health";

  const DATASETS_URL = "/dataset-runs";
  const DATASET_SETTINGS_URL = "/dataset-runs/settings";

  const POLL_INTERVAL = 800;            // manual experiment status poll
  const DATASET_POLL_INTERVAL = 2500;   // dataset run status poll
  const FINALIZE_GRACE_POLLS = 12;      // extra fast polls while finalizing
  const FINALIZE_GRACE_INTERVAL = 1000;

  const IKE_VERSION = 2;

  const ENCRYPTION_LABELS = {
    aes128: "AES-128-CBC",
    aes256: "AES-256-CBC",
    aes128gcm16: "AES-128-GCM",
    aes256gcm16: "AES-256-GCM",
    aes128cbc: "AES-128-CBC",
    aes256cbc: "AES-256-CBC",
  };
  const INTEGRITY_LABELS = {
    sha256: "HMAC-SHA256",
    sha384: "HMAC-SHA384",
    sha512: "HMAC-SHA512",
  };
  const DH_LABELS = {
    modp2048: "DH Group 14 / modp2048",
    modp3072: "DH Group 15 / modp3072",
    modp4096: "DH Group 16 / modp4096",
  };
  const MODE_LABELS = { tunnel: "Tunnel", transport: "Transport" };
  const FAMILY_LABELS = { ipv4: "IPv4", ipv6: "IPv6" };
  const TRAFFIC_LABELS = {
    icmp: "ICMP",
    voip: "VoIP-like",
    messaging: "Messaging-like",
    email: "Email-like",
    web: "Web-like",
    video: "Video-like",
  };
  const POSTURE_ORDER = ["STRONG", "GOOD", "MEDIUM", "WEAK", "WORST"];
  const TRAFFIC_ORDER = ["voip", "video", "messaging", "email", "web", "icmp"];

  const TERMINAL_STATUSES = ["COMPLETED", "FAILED"];

  const GCM_CIPHERS = ["aes128gcm16", "aes256gcm16"];

  const STAGE_DEFS = [
    { key: "QUEUED", label: "Queued" },
    { key: "DEPLOY", label: "Deploying Topology" },
    { key: "IPSEC", label: "Establishing IPsec" },
    { key: "OBSERVATION", label: "Preparing Live Observation" },
    { key: "CONNECTIVITY", label: "Verifying Connectivity" },
    { key: "TRAFFIC", label: "Generating Traffic" },
    { key: "COMPLETED", label: "Complete" },
  ];

  const STAGE_LABELS = {
    QUEUED: "Queued",
    RUNNING: "Starting",
    DEPLOY: "Deploying Topology",
    IPSEC: "Establishing IPsec",
    OBSERVATION: "Preparing Live Observation",
    CONNECTIVITY: "Verifying Connectivity",
    TRAFFIC: "Generating Traffic",
    COMPLETED: "Completed",
    CONFIGURATION: "Configuration",
    EXPERIMENT: "Controller",
  };

  let state = {
    mode: "tunnel",
    family: "ipv4",
    pfs: true,
    running: false,
    lastPayload: null,
    // The controller's own identifier for the most recent experiment. Retained
    // after completion because it is what the completed run is known by
    // elsewhere; never reconstructed here, because only the controller issues
    // it.
    lastJob: null,
    configurations: null,
    duration: { min: 10, max: 120, default: 30 },
    espHmacs: ["sha256", "sha384", "sha512"],
    dataset: {
      settings: null,        // { maximum_target_samples }
      activeRunId: null,     // dataset_run_id of the active/observed run
      status: null,          // last DatasetRunStatusResponse payload
      results: null,         // last DatasetRunResultsResponse payload
      error: null,           // user-facing error, if any
      busy: false,           // a dataset request is in flight
      pollToken: 0,          // invalidated on every (re)start/stop
      pollTimer: null,
    },
  };

  let healthTimer = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  function show(el) { el.classList.remove("is-hidden"); }
  function hide(el) { el.classList.add("is-hidden"); }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function isGcm(cipher) {
    return GCM_CIPHERS.indexOf(cipher) !== -1;
  }

  function label(key) {
    return (
      ENCRYPTION_LABELS[key] ||
      INTEGRITY_LABELS[key] ||
      DH_LABELS[key] ||
      MODE_LABELS[key] ||
      FAMILY_LABELS[key] ||
      key
    );
  }

  function fillSelect(sel, options, labelMap, defaultVal) {
    sel.innerHTML = "";
    if (!options || !options.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "Unavailable";
      sel.appendChild(opt);
      return;
    }
    for (const v of options) {
      const opt = document.createElement("option");
      opt.value = String(v);
      opt.textContent = (labelMap && labelMap[String(v)]) || String(v);
      sel.appendChild(opt);
    }
    if (defaultVal != null && options.indexOf(defaultVal) !== -1) {
      sel.value = String(defaultVal);
    }
  }

  /* ---------- SVG icons ---------- */

  function serverSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><path d="M6 7h.01M6 18h.01"/></svg>';
  }

  function gwSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M7.5 11l10-5.2M7.5 13l10 5.2"/></svg>';
  }

  function lockSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 118 0v4"/></svg>';
  }

  function arrowSvg(cls) {
    return '<svg class="' + cls + '" viewBox="0 0 24 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M0 6h20M15 1l5 5-5 5"/></svg>';
  }

  /* ---------- Segmented controls (API-driven) ---------- */

  function buildSegmented(containerSel, values, labelMap, stateKey) {
    const host = $(containerSel);
    host.innerHTML = "";
    for (const v of values) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "seg-option";
      btn.dataset.value = String(v);
      btn.setAttribute("role", "radio");
      btn.setAttribute("aria-checked", "false");
      btn.textContent = (labelMap && labelMap[String(v)]) || String(v);
      btn.addEventListener("click", () => {
        if (state.running) return;
        $$(containerSel + " .seg-option").forEach((b) => {
          b.classList.remove("active");
          b.setAttribute("aria-checked", "false");
        });
        btn.classList.add("active");
        btn.setAttribute("aria-checked", "true");
        state[stateKey] = v;
        if (stateKey === "mode") {
          buildFlow();
        }
        updateSummary();
      });
      host.appendChild(btn);
    }
    const match = $$(containerSel + " .seg-option").find(
      (b) => b.dataset.value === String(state[stateKey])
    );
    if (match) {
      match.classList.add("active");
      match.setAttribute("aria-checked", "true");
    } else {
      const first = $$(containerSel + " .seg-option")[0];
      if (first) {
        first.classList.add("active");
        first.setAttribute("aria-checked", "true");
        state[stateKey] = first.dataset.value;
      }
    }
  }

  function syncDurationLabel() {
    const d = state.duration || {};
    const el = $("#durationUnit");
    if (el) {
      el.textContent = "sec (" + (d.min != null ? d.min : 10) + "\u2013" + (d.max != null ? d.max : 120) + ")";
    }
  }

  /* ---------- Payload & configuration ---------- */

  function getPayload() {
    const espEnc = $("#espEncryption").value;
    const gcm = isGcm(espEnc);

    let duration = parseInt($("#trafficDuration").value, 10);
    if (isNaN(duration)) {
      duration = state.duration.default != null ? state.duration.default : 30;
    }
    duration = Math.min(Math.max(duration, state.duration.min), state.duration.max);

    return {
      mode: state.mode,
      address_family: state.family,
      ike: {
        version: IKE_VERSION,
        encryption: $("#ikeEncryption").value,
        integrity: $("#ikeIntegrity").value,
        dh_group: $("#ikeDh").value,
      },
      esp: {
        encryption: espEnc,
        integrity: gcm ? null : $("#espIntegrity").value,
        dh_group: $("#espDh").value,
        pfs: state.pfs,
      },
      traffic: {
        profile: $("#trafficProfile").value,
        duration: duration,
      },
    };
  }

  function applyEspIntegrityState() {
    const gcm = isGcm($("#espEncryption").value);
    const sel = $("#espIntegrity");
    const note = $("#espIntegrityNote");

    if (gcm) {
      sel.innerHTML = "";
      const none = document.createElement("option");
      none.value = "";
      none.textContent = "None";
      sel.appendChild(none);
      sel.disabled = true;
      $("#espIntegrityField").classList.add("is-muted");
      note.classList.remove("is-hidden");
    } else {
      fillSelect(sel, state.espHmacs, INTEGRITY_LABELS, "sha256");
      sel.disabled = false;
      $("#espIntegrityField").classList.remove("is-muted");
      note.classList.add("is-hidden");
    }
  }

  /* ---------- Key/value rows ---------- */

  function keysValues(p) {
    const rows = [
      ["Mode", MODE_LABELS[p.mode] || p.mode, false],
      ["Address Family", FAMILY_LABELS[p.address_family] || p.address_family, false],
      ["IKE", (ENCRYPTION_LABELS[p.ike.encryption] || p.ike.encryption) + " / " +
            (INTEGRITY_LABELS[p.ike.integrity] || p.ike.integrity) + " / " +
            (DH_LABELS[p.ike.dh_group] || p.ike.dh_group), false],
      ["ESP", (ENCRYPTION_LABELS[p.esp.encryption] || p.esp.encryption) + " / " +
             (p.esp.integrity ? (INTEGRITY_LABELS[p.esp.integrity] || p.esp.integrity) : "None"), p.esp.integrity ? false : true],
      ["PFS", p.esp.pfs ? "Enabled" : "Disabled", false],
    ];
    if (p.traffic) {
      rows.push([
        "Traffic",
        (TRAFFIC_LABELS[p.traffic.profile] || p.traffic.profile) + " / " + p.traffic.duration + " sec",
        false,
      ]);
    }
    return rows;
  }

  function keyValueRowsHtml(p, base) {
    return keysValues(p)
      .map(function (kv) {
        return (
          '<div class="' + base + '-row">' +
            '<span class="' + base + '-key">' + escapeHtml(kv[0]) + "</span>" +
            '<span class="' + base + "-val" + (kv[2] ? " na" : "") + '">' + escapeHtml(kv[1]) + "</span>" +
          "</div>"
        );
      })
      .join("");
  }

  function updateSummary() {
    $("#summaryLines").innerHTML = keyValueRowsHtml(getPayload(), "summary");
  }

  /* ---------- Flow painting ---------- */

  function paintFlow(activeKeys, doneKeys) {
    $$(".flow-step").forEach((el) => {
      const k = el.dataset.step;
      el.classList.toggle("active", activeKeys.indexOf(k) !== -1);
      el.classList.toggle("done", doneKeys.indexOf(k) !== -1);
    });
  }

  function buildFlow() {
    const mode = state.mode;
    const family = state.family;
    $("#flowSub").textContent =
      (MODE_LABELS[mode] || mode) + " mode \u2014 " +
      (mode === "tunnel" ? "network-to-network" : "host-to-host") +
      (family === "ipv6" ? " \u00b7 IPv6" : "");

    if (mode === "tunnel") {
      $("#flowDiagram").innerHTML =
        '<div class="node">' +
          '<div class="node-ico">' + serverSvg() + "</div>" +
          '<div class="node-name">HOST A</div>' +
          '<div class="node-role">LAN host</div>' +
        "</div>" +
        '<div class="conn">' + arrowSvg("arrow") + "</div>" +
        '<div class="node">' +
          '<div class="node-ico">' + gwSvg() + "</div>" +
          '<div class="node-name">IPsec Gateway A</div>' +
        "</div>" +
        '<div class="conn-secure">' +
          '<div class="sec-line"></div>' +
          '<div class="sec-pill">' +
            '<span class="lock">' + lockSvg() + "</span>" +
            "Encrypted IPsec" +
          "</div>" +
          '<div class="sec-line"></div>' +
        "</div>" +
        '<div class="node">' +
          '<div class="node-ico">' + gwSvg() + "</div>" +
          '<div class="node-name">IPsec Gateway B</div>' +
        "</div>" +
        '<div class="conn">' + arrowSvg("arrow") + "</div>" +
        '<div class="node">' +
          '<div class="node-ico">' + serverSvg() + "</div>" +
          '<div class="node-name">HOST B</div>' +
          '<div class="node-role">LAN host</div>' +
        "</div>";
    } else {
      $("#flowDiagram").innerHTML =
        '<div class="node">' +
          '<div class="node-ico">' + serverSvg() + "</div>" +
          '<div class="node-name">HOST C</div>' +
        "</div>" +
        '<div class="conn-secure">' +
          '<div class="sec-line"></div>' +
          '<div class="sec-pill">' +
            '<span class="lock">' + lockSvg() + "</span>" +
            "Encrypted IPsec" +
          "</div>" +
          '<div class="sec-line"></div>' +
        "</div>" +
        '<div class="node">' +
          '<div class="node-ico">' + serverSvg() + "</div>" +
          '<div class="node-name">HOST D</div>' +
        "</div>";
    }
  }

  /* ---------- Manual experiment progress (backend stage timeline) ---------- */

  function renderStageTimeline(states) {
    $("#stageTimeline").innerHTML = STAGE_DEFS.map(function (def) {
      const s = states[def.key] || "pending";
      return (
        '<div class="stage-row ' + s + '">' +
          '<span class="stage-dot" aria-hidden="true"></span>' +
          '<span class="stage-name">' + def.label + "</span>" +
          (s === "active" ? '<span class="stage-state">running</span>' : "") +
        "</div>"
      );
    }).join("");
  }

  function setJobState(status) {
    const el = $("#jobStateLabel");
    el.className = "job-state st-" + String(status || "").toLowerCase();
    el.textContent = STAGE_LABELS[status] || String(status || "");
  }

  function stageIndexOf(stage) {
    return STAGE_DEFS.findIndex((d) => d.key === stage);
  }

  function paintProgress(status, stage) {
    const states = {};
    STAGE_DEFS.forEach((d) => { states[d.key] = "pending"; });

    if (status === "QUEUED") {
      states.QUEUED = "active";
      $("#stageCaption").textContent = "Waiting for the testbed slot to become available.";
    } else if (status === "RUNNING") {
      const stageKey = STAGE_DEFS.some((d) => d.key === stage) ? stage : "QUEUED";
      let started = false;
      STAGE_DEFS.forEach((d) => {
        if (d.key === stageKey) {
          states[d.key] = "active";
          started = true;
        } else if (!started) {
          states[d.key] = "done";
        }
      });
      $("#stageCaption").textContent =
        stageKey === "QUEUED"
          ? "Preparing the experiment."
          : (STAGE_LABELS[stageKey] || stageKey) + " \u2014 " + stageCaptionText(stageKey);
    } else if (status === "COMPLETED") {
      STAGE_DEFS.forEach((d) => { states[d.key] = "done"; });
      $("#stageCaption").textContent = "The controller has finished the experiment.";
    } else if (status === "FAILED") {
      const failIdx = STAGE_DEFS.findIndex((d) => d.key === stage);
      if (failIdx > 0) {
        STAGE_DEFS.forEach((d, i) => {
          if (i < failIdx) states[d.key] = "done";
          else if (i === failIdx) states[d.key] = "fail";
        });
        $("#stageCaption").textContent = "Failed during " + (STAGE_LABELS[stage] || stage).toLowerCase() + ".";
      } else {
        STAGE_DEFS[0] && (states[STAGE_DEFS[0].key] = "fail");
        const label = stageLabel(stage);
        $("#stageCaption").textContent = label
          ? "Failed during " + label.toLowerCase() + "."
          : "The controller stopped the experiment.";
      }
    } else {
      states.QUEUED = "active";
      $("#stageCaption").textContent = "";
    }

    renderStageTimeline(states);
  }

  function stageCaptionText(stageKey) {
    if (stageKey === "DEPLOY") return "deploying the Containerlab topology.";
    if (stageKey === "IPSEC") return "establishing the IPsec security associations.";
    if (stageKey === "OBSERVATION") return "attaching the live XDP observation feed.";
    if (stageKey === "CONNECTIVITY") return "verifying end-to-end connectivity.";
    if (stageKey === "TRAFFIC") return "generating the selected traffic profile.";
    return "";
  }

  function stageLabel(stage) {
    return STAGE_LABELS[stage] || stage || "";
  }

  /* ---------- Manual experiment results ---------- */

  function resetResultStates() {
    hide($("#emptyState"));
    hide($("#passState"));
    hide($("#failState"));
    hide($("#rejectState"));
    show($("#progressWrap"));
  }

  function renderCompletedRun(jobId) {
    const job = $("#passFullJobId");
    if (job && jobId) {
      job.textContent = jobId;
      show($("#passHandoff"));
    }
    const handoff = $("#passHandoffNote");
    if (handoff) {
      handoff.textContent =
        "To compare a run against a baseline, record the baseline first (Transport + IPv4), " +
        "then run the configuration to compare against it (Transport + IPv6). Every completed " +
        "experiment is listed in Sentinel under the assessment id the backend assigns it \u2014 " +
        "open that assessment there to read its drift comparison.";
    }
    const note = $("#passCompletedNote");
    if (note) {
      note.textContent =
        "Completed " + new Date().toLocaleTimeString() + " \u2014 this experiment is now " +
        "recorded by the analytics backend.";
      show(note);;
    }
  }

  function renderPass(result, jobId) {
    hide($("#progressWrap"));

    const ip = result.ipsec || {};
    const con = result.connectivity || {};
    const tra = result.traffic || {};

    $("#passJobId").textContent = jobId ? "Experiment " + jobId.slice(0, 8) : "\u2014";
    state.lastJob = jobId ? { jobId: jobId, status: "COMPLETED" } : null;
    renderCompletedRun(jobId);
    $("#mIke").textContent = ip.ike_sa || "\u2014";
    $("#mChild").textContent = ip.child_sa || "\u2014";
    $("#mMode").textContent = ip.mode || "\u2014";
    $("#mConStatus").textContent = con.status || "\u2014";
    $("#mLoss").textContent = con.packet_loss != null ? Math.round(con.packet_loss) + "%" : "\u2014";
    $("#mTrafficProfile").textContent = tra.profile ? (TRAFFIC_LABELS[tra.profile] || tra.profile) : "\u2014";
    $("#mTrafficPackets").textContent = tra.packets != null ? String(tra.packets) : "\u2014";
    $("#mTrafficBitrate").textContent =
      tra.bitrate_bps != null
        ? formatBitrate(tra.bitrate_bps)
        : "\u2014";

    $("#passConfig").innerHTML = state.lastPayload ? keyValueRowsHtml(state.lastPayload, "conf") : "";

    show($("#passState"));
  }

  function formatBitrate(bps) {
    const n = Number(bps);
    if (!isFinite(n) || n < 0) return "\u2014";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " Mbps";
    if (n >= 1e3) return Math.round(n / 1e3) + " kbps";
    return Math.round(n) + " bps";
  }

  function finalizeFail(stage, message, jobId) {
    hide($("#progressWrap"));

    const stg = stage || "err controller";
    $("#failJobId").textContent = jobId ? "Experiment " + jobId.slice(0, 8) : "\u2014";
    $("#failStage").innerHTML = "Failed at <b>" + escapeHtml(stg) + "</b>";
    $("#failMessage").textContent = message || "The experiment could not be completed.";

    $("#failConfig").innerHTML = state.lastPayload ? keyValueRowsHtml(state.lastPayload, "conf") : "";

    show($("#failState"));
  }

  function finalizeReject(message) {
    hide($("#progressWrap"));

    $("#rejectMessage").textContent = message || "The experiment could not be started.";

    show($("#rejectState"));
  }

  /* ---------- Error classification ---------- */

  function classifyError(status, detail) {
    const d = String(detail || "").toLowerCase();

    if (status === 400) {
      return { stage: "Configuration", message: detail || "The selected configuration is not supported by the testbed." };
    }
    if (/config/.test(d)) {
      return { stage: "Configuration", message: detail };
    }
    if (/deploy|topology|container|docker|clab/.test(d)) {
      return { stage: "Deploying Topology", message: detail };
    }
    if (/ike|established|firewall|keying|auth/.test(d)) {
      return { stage: "Establishing IPsec", message: detail };
    }
    if (/child|installed/.test(d)) {
      return { stage: "CHILD SA", message: detail };
    }
    if (/ping|packet loss|connect/.test(d)) {
      return { stage: "Verifying Connectivity", message: detail };
    }
    if (/traffic|profile|bitrate|listener/.test(d)) {
      return { stage: "Generating Traffic", message: detail };
    }
    if (/xdp|observation|monitor|live journal/.test(d)) {
      return { stage: "Live Observation", message: detail };
    }
    return { stage: "Controller", message: detail || "The experiment could not be run." };
  }

  async function readDetail(res) {
    try {
      const j = await res.json();
      if (j && typeof j.detail === "string") {
        return j.detail;
      }
      if (j && Array.isArray(j.detail)) {
        return j.detail
          .map(function (d) {
            const loc = d.loc && d.loc.length ? " (" + d.loc.join(".") + ")" : "";
            return (d.msg || "Invalid value") + loc;
          })
          .join("; ");
      }
      return "";
    } catch (_) {
      return "";
    }
  }

  /* ---------- Manual experiment run ---------- */

  function setRunningUI(on) {
    const runBtn = $("#runBtn");
    const runLabel = $("#runLabel");
    runBtn.disabled = on;
    runBtn.classList.toggle("is-running", on);
    runLabel.textContent = on ? "Running\u2026" : "Run Experiment";
    $("#configCard").classList.toggle("is-disabled", on);
  }

  function validatePayload(p) {
    const espEnc = p.esp.encryption;
    if (isGcm(espEnc)) {
      if (p.esp.integrity !== null) {
        return "AES-GCM must use ESP integrity None.";
      }
    } else {
      if (!p.esp.integrity) {
        return "AES-CBC requires an ESP integrity algorithm.";
      }
      if (state.espHmacs.indexOf(p.esp.integrity) === -1) {
        return "Unsupported ESP integrity for AES-CBC.";
      }
    }
    if (!p.traffic.profile) {
      return "Select a traffic profile.";
    }
    if (!(p.traffic.duration >= state.duration.min && p.traffic.duration <= state.duration.max)) {
      return "Traffic duration is outside the supported range.";
    }
    return null;
  }

  async function runExperiment() {
    if (state.running) return;

    state.running = true;
    setRunningUI(true);

    resetResultStates();
    state.lastPayload = getPayload();

    const invalid = validatePayload(state.lastPayload);
    if (invalid) {
      finalizeReject(invalid);
      setRunningUI(false);
      state.running = false;
      return;
    }

    $("#jobIdText").textContent = "\u2014";
    paintProgress("QUEUED", "QUEUED");
    setJobState("QUEUED");

    try {
      let res;
      try {
        res = await fetch(EXPERIMENTS_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(state.lastPayload),
        });
      } catch (_) {
        throw { network: true };
      }

      if (!res.ok) {
        const detail = await readDetail(res);

        if (res.status === 409) {
          finalizeReject(detail || "Another experiment is already running (or the testbed is busy with another run).");
          return;
        }
        if (res.status === 422) {
          finalizeFail("Configuration", detail || "The controller rejected the selected configuration.");
          return;
        }

        const c = classifyError(res.status, detail);
        finalizeFail(c.stage, c.message);
        return;
      }

      let jobId = null;
      try {
        const startData = await res.json();
        jobId = startData && startData.job_id;
      } catch (_) {
        finalizeReject("The controller returned an invalid response.");
        return;
      }

      if (!jobId) {
        finalizeReject("The controller did not return a job identifier.");
        return;
      }

      state.lastJob = { jobId: jobId, status: "RUNNING" };
      $("#jobIdText").textContent = jobId.slice(0, 8);

      while (true) {
        await sleep(POLL_INTERVAL);

        let statusRes;
        try {
          statusRes = await fetch(EXPERIMENTS_URL + "/" + encodeURIComponent(jobId));
        } catch (_) {
          throw { network: true };
        }

        if (statusRes.status === 404) {
          finalizeReject("The experiment job no longer exists on the controller.");
          return;
        }
        if (!statusRes.ok) {
          finalizeReject("The controller could not be reached while monitoring the experiment.");
          return;
        }

        const job = await statusRes.json();

        paintProgress(job.status, job.stage);
        setJobState(job.status);
        if (state.lastJob && job.status !== "COMPLETED") {
          state.lastJob = { jobId: state.lastJob.jobId, status: job.status };
        }

        if (job.status === "COMPLETED") {
          const result = job.result;

          if (result && result.status === "PASS") {
            renderPass(result, jobId);
          } else {
            const con = (result && result.connectivity) || {};
            const loss = con.packet_loss;
            const msg = loss != null
              ? "Connectivity verification failed: " + Math.round(loss) + "% packet loss."
              : "The experiment completed but did not report a PASS result.";
            finalizeFail("Verifying Connectivity", msg, jobId);
          }
          return;
        }

        if (job.status === "FAILED") {
          const stg = stageLabel(job.stage) || "Controller";
          finalizeFail(stg, job.error || "The experiment could not be completed.", jobId);
          return;
        }
      }
    } catch (err) {
      if (err && err.network) {
        finalizeReject("Unable to connect to the IPsec testbed controller.");
      } else {
        finalizeReject("An unexpected error occurred while running the experiment.");
      }
    } finally {
      setRunningUI(false);
      state.running = false;
    }
  }

  /* ---------- Health ---------- */

  async function checkHealth() {
    try {
      const res = await fetch(HEALTH_URL);
      const data = await res.json();
      const ok = data && data.status === "ok";
      $("#statusPill").classList.toggle("is-offline", !ok);
      $("#statusText").textContent = ok ? "Testbed Ready" : "Testbed Unavailable";
    } catch (_) {
      $("#statusPill").classList.add("is-offline");
      $("#statusText").textContent = "Controller Offline";
    }
  }

  /* ---------- Manual option loading (single backend source of truth) ---------- */

  async function loadConfigurations() {
    let data = null;
    try {
      const res = await fetch(CONFIGS_URL);
      if (res.ok) {
        data = await res.json();
      }
    } catch (_) {}

    const available = data && data.ike && data.esp;
    if (!available) {
      ["ikeEncryption", "ikeIntegrity", "ikeDh", "espEncryption", "espIntegrity", "espDh", "trafficProfile"].forEach((id) => {
        const sel = $("#" + id);
        if (sel) {
          sel.innerHTML = "";
          const opt = document.createElement("option");
          opt.value = "";
          opt.textContent = "Unavailable";
          sel.appendChild(opt);
        }
      });
      $("#statusPill").classList.add("is-offline");
      $("#statusText").textContent = "Configurations Unavailable";
      setRunningUI(false);
      $("#runBtn").disabled = true;
      return;
    }

    state.configurations = data;
    state.espHmacs = (data.esp.integrity || ["sha256", "sha384", "sha512"]).slice();
    if (
      data.traffic &&
      data.traffic.duration &&
      typeof data.traffic.duration.min === "number"
    ) {
      state.duration = data.traffic.duration;
    }
    state.mode = data.modes && data.modes.length ? data.modes[0] : state.mode;
    state.family =
      data.address_families && data.address_families.length
        ? data.address_families[0]
        : state.family;

    buildSegmented("#modeSegmented", data.modes || ["tunnel", "transport"], MODE_LABELS, "mode");
    buildSegmented("#familySegmented", data.address_families || ["ipv4", "ipv6"], FAMILY_LABELS, "family");

    fillSelect($("#ikeEncryption"), data.ike.encryption, ENCRYPTION_LABELS, "aes256");
    fillSelect($("#ikeIntegrity"), data.ike.integrity, INTEGRITY_LABELS, "sha256");
    fillSelect($("#ikeDh"), data.ike.dh_groups, DH_LABELS, "modp2048");
    fillSelect($("#espEncryption"), data.esp.encryption, ENCRYPTION_LABELS, "aes256gcm16");

    const dur = $("#trafficDuration");
    dur.min = state.duration.min;
    dur.max = state.duration.max;
    dur.value = state.duration.default;
    syncDurationLabel();

    const profiles = (data.traffic && data.traffic.profiles) || ["icmp", "voip", "messaging", "email", "web", "video"];
    fillSelect($("#trafficProfile"), profiles, TRAFFIC_LABELS, "web");

    fillSelect($("#espDh"), data.esp.dh_groups, DH_LABELS, "modp2048");
    applyEspIntegrityState();
    updateSummary();
    buildFlow();
  }

  /* =======================================================================
   * Automated experiment run UI (formerly "dataset generation")
   * ======================================================================= */

  const D = () => state.dataset;

  function datasetBadgeClass(status) {
    const s = String(status || "").toUpperCase();
    if (s === "RUNNING" || s === "CREATED") return "ds-badge-running";
    if (s === "PAUSED") return "ds-badge-paused";
    if (s === "COMPLETED") return "ds-badge-completed";
    if (s === "FAILED") return "ds-badge-failed";
    return "ds-badge-idle";
  }

  function datasetBadgeText(status) {
    const s = String(status || "").toUpperCase();
    if (s === "RUNNING") return "Running";
    if (s === "CREATED") return "Started";
    if (s === "PAUSED") return "Paused";
    if (s === "COMPLETED") return "Completed";
    if (s === "FAILED") return "Failed";
    return "Idle";
  }

  function datasetConfigRows(cfg) {
    if (!cfg || typeof cfg !== "object") return "";
    const ike = cfg.ike || {};
    const esp = cfg.esp || {};
    const rows = [
      ["Mode", MODE_LABELS[cfg.mode] || cfg.mode],
      ["Address Family", FAMILY_LABELS[cfg.address_family] || cfg.address_family],
      ["IKE Version", ike.version != null ? "IKEv" + ike.version : "\u2014"],
      ["IKE Encryption", ENCRYPTION_LABELS[ike.encryption] || ike.encryption || "\u2014"],
      ["IKE Integrity", INTEGRITY_LABELS[ike.integrity] || ike.integrity || "\u2014"],
      ["IKE DH", DH_LABELS[ike.dh_group] || ike.dh_group || "\u2014"],
      ["ESP Encryption", ENCRYPTION_LABELS[esp.encryption] || esp.encryption || "\u2014"],
      // GCM has no separate ESP integrity: the backend reports null.
      ["ESP Integrity", esp.integrity ? (INTEGRITY_LABELS[esp.integrity] || esp.integrity) : "None"],
      ["ESP DH", DH_LABELS[esp.dh_group] || esp.dh_group || "\u2014"],
      ["PFS", esp.pfs ? "On" : "Off"],
    ];
    return rows
      .map(function (r) {
        return (
          '<div class="ds-cfg-row">' +
            '<span class="ds-cfg-key">' + escapeHtml(r[0]) + "</span>" +
            '<span class="ds-cfg-val">' + escapeHtml(r[1]) + "</span>" +
          "</div>"
        );
      })
      .join("");
  }

  function currentBlockHtml(st) {
    const seq = st.current_sequence;
    const target = st.target_samples;
    const profile = st.current_traffic_profile;
    const posture = st.current_security_posture;
    const cfg = st.current_configuration;

    if (seq == null && !profile && !posture && !cfg) return "";

    const chips = [];
    if (seq != null) {
      chips.push(
        '<div class="ds-chip"><span class="ds-chip-label">Sequence</span><span class="ds-chip-val">' +
          seq + (target != null ? " / " + target : "") + "</span></div>"
      );
    }
    if (profile) {
      chips.push(
        '<div class="ds-chip"><span class="ds-chip-label">Traffic</span><span class="ds-chip-val">' +
          escapeHtml(TRAFFIC_LABELS[profile] || profile) + "</span></div>"
      );
    }
    if (posture) {
      let badge;
      if (POSTURE_ORDER.indexOf(posture) !== -1) {
        badge = '<span class="posture-badge p-' + posture.toLowerCase() + '">' + escapeHtml(posture) + "</span>";
      } else {
        badge = escapeHtml(posture);
      }
      chips.push(
        '<div class="ds-chip"><span class="ds-chip-label">Security</span><span class="ds-chip-val">' +
          badge + "</span></div>"
      );
    }

    const cfgRows = datasetConfigRows(cfg);
    return (
      '<div class="ds-current">' +
        '<div class="ds-current-title">Currently running experiment</div>' +
        '<div class="ds-chips">' + chips.join("") + "</div>" +
        (cfgRows ? '<div class="ds-cfg">' + cfgRows + "</div>" : "") +
      "</div>"
    );
  }

  function renderDataset() {
    const d = D();
    const st = d.status;
    const statusEl = $("#datasetStatus");
    const badgeEl = $("#datasetStatusBadge");
    const genBtn = $("#datasetGenerateBtn");
    const errEl = $("#datasetError");

    const active = d.activeRunId && st;
    const statusName = st ? st.status : null;
    const executing =
      statusName === "RUNNING" || statusName === "CREATED" || statusName === "PAUSED";

    badgeEl.className = "ds-badge " + datasetBadgeClass(statusName || (active ? "CREATED" : ""));
    badgeEl.textContent = datasetBadgeText(statusName || (active ? "CREATED" : ""));
    genBtn.disabled = !!d.busy || executing;

    if (d.error) {
      errEl.textContent = d.error;
      errEl.classList.remove("is-hidden");
    } else {
      errEl.textContent = "";
      errEl.classList.add("is-hidden");
    }

    if (!active) {
      statusEl.innerHTML =
        '<div class="ds-idle">' +
          '<div class="ds-idle-title">No active automated run</div>' +
          '<div class="ds-idle-sub">Set the exact number of successful experiments above and start. ' +
          "The backend plans one experiment per IPsec&nbsp;configuration&nbsp;&times;&nbsp;traffic&nbsp;profile " +
          "combination and repeats the testbed until the requested number of <b>successful</b> experiments are committed.</div>" +
        "</div>";
      return;
    }

    const target = st.target_samples;
    const successful = st.successful_samples || 0;
    const attempted = st.attempted_runs || 0;
    const failed = st.failed_samples || 0;
    const interrupted = st.interrupted_samples || 0;
    let pct = st.progress_percentage;
    if (typeof pct !== "number" || !isFinite(pct)) {
      pct = target > 0 ? (successful / target) * 100 : 0;
    }
    const safePct = Math.max(0, Math.min(100, pct));

    let banner = "";
    let extras = "";

    if (statusName === "COMPLETED") {
      const finalized = !!(st.finalization && st.finalization.status === "COMPLETED");
      banner =
        '<div class="ds-banner ds-banner-ok">' +
          '<span class="ds-banner-check" aria-hidden="true">&#10003;</span>' +
          "<div><b>Automated run completed</b> &mdash; " + successful + " / " + target +
          " successful experiments.</div>" +
        "</div>";
      if (finalized) {
        extras =
          '<button type="button" class="run-btn ds-download-btn" id="datasetDownloadBtn">' +
          "Download dataset export (legacy)</button>" +
          '<div class="ds-download-note">Legacy dataset archive: features.parquet + metadata.jsonl + manifest.json + README.txt. Not a raw PCAP capture.</div>';
      }
    } else if (statusName === "PAUSED") {
      banner =
        '<div class="ds-banner ds-banner-warn">' +
          "<div><b>Run paused</b> &mdash; the run can be resumed.</div>" +
          "</div>";
      extras =
        '<button type="button" class="run-btn ds-resume-btn" id="datasetResumeBtn">Resume Run</button>';
    } else if (statusName === "FAILED") {
      const msg = (st.error && st.error.trim())
        ? st.error
        : ((st.finalization && st.finalization.error) || "The automated run failed.");
      banner =
        '<div class="ds-banner ds-banner-err">' +
          "<div><b>Automated run failed</b> &mdash; " + escapeHtml(msg) + "</div>" +
        "</div>";
    }

    statusEl.innerHTML =
      '<div class="ds-progress">' +
        '<div class="ds-progress-head">' +
          '<span class="ds-run-label">Automated run</span>' +
          '<code class="dataset-run-id">' + escapeHtml(d.activeRunId) + "</code>" +
        "</div>" +
        banner +
        '<div class="ds-count">' +
          '<div class="ds-count-num">' + successful + " / " + target + "</div>" +
          '<div class="ds-count-label">successful experiments</div>' +
        "</div>" +
        '<div class="ds-bar" role="progressbar" aria-valuenow="' + Math.round(safePct) +
          '" aria-valuemin="0" aria-valuemax="100">' +
          '<div class="ds-bar-fill" style="width:' + safePct + '%"></div>' +
        "</div>" +
        '<div class="ds-bar-caption">' + Math.round(safePct) + "% &mdash; progress is based only on successful experiments</div>" +
        '<div class="ds-metrics">' +
          '<div class="ds-metric"><span class="ds-metric-label">Attempts</span><span class="ds-metric-num">' + attempted + "</span></div>" +
          '<div class="ds-metric"><span class="ds-metric-label">Failed</span><span class="ds-metric-num">' + failed + "</span></div>" +
          '<div class="ds-metric"><span class="ds-metric-label">Interrupted</span><span class="ds-metric-num">' + interrupted + "</span></div>" +
        "</div>" +
        (statusName === "RUNNING" || statusName === "CREATED" ? currentBlockHtml(st) : "") +
        extras +
      "</div>";
  }

  function renderStats() {
    const d = D();
    const emptyEl = $("#statsEmpty");
    const gridEl = $("#statsGrid");

    if (!d.results) {
      emptyEl.classList.remove("is-hidden");
      gridEl.classList.add("is-hidden");
      return;
    }

    emptyEl.classList.add("is-hidden");
    gridEl.classList.remove("is-hidden");

    const res = d.results;
    renderDistribution($("#trafficDist"), res.traffic_distribution, TRAFFIC_LABELS, TRAFFIC_ORDER);
    renderDistribution($("#postureDist"), res.security_posture_distribution, null, POSTURE_ORDER, true);

    const successful = res.successful_samples != null ? res.successful_samples : "\u2014";
    let summaryRows = [
      ["Run ID", res.dataset_run_id || "\u2014"],
      ["Target", res.target_samples != null ? res.target_samples : "\u2014"],
      ["Successful experiments", successful],
      ["Attempts", res.attempted_runs != null ? res.attempted_runs : "\u2014"],
      ["Failures", res.failed_samples != null ? res.failed_samples : "\u2014"],
      ["Interruptions", res.interrupted_samples != null ? res.interrupted_samples : "\u2014"],
    ];
    if (res.feature_row_count != null) {
      summaryRows.push(["Feature rows (legacy export)", res.feature_row_count]);
    }
    if (res.metadata_record_count != null) {
      summaryRows.push(["Ground-truth metadata records", res.metadata_record_count]);
    }
    if (res.finalization && res.finalization.status) {
      summaryRows.push(["Finalization", res.finalization.status]);
    }
    $("#statsSummary").innerHTML = summaryRows
      .map(function (r) {
        return (
          '<div class="dist-sum-row">' +
            '<span class="dist-sum-key">' + escapeHtml(r[0]) + "</span>" +
            '<span class="dist-sum-val">' + escapeHtml(r[1]) + "</span>" +
          "</div>"
        );
      })
      .join("");
  }

  function renderDistribution(listEl, dist, labelMap, order, posture) {
    const unknown = {};
    if (dist && typeof dist === "object") {
      order.forEach(function (k) {
        if (dist[k] != null) {
          unknown[k] = Number(dist[k]) || 0;
        }
      });
      Object.keys(dist).forEach(function (k) {
        if (unknown[k] == null) {
          unknown[k] = Number(dist[k]) || 0;
        }
      });
    }

    const entries = Object.keys(unknown);
    if (!entries.length) {
      listEl.innerHTML = '<div class="dist-none">No committed samples yet.</div>';
      return;
    }

    const total = entries.reduce(function (acc, k) { return acc + (unknown[k] || 0); }, 0) || 1;

    listEl.innerHTML = entries
      .map(function (k) {
        const count = unknown[k];
        const pct = Math.round((count / total) * 100);
        const pretty = labelMap ? (labelMap[k] || k) : k;
        return (
          '<div class="dist-row">' +
            '<span class="dist-label">' + escapeHtml(pretty) + "</span>" +
            '<span class="dist-bar"><span class="dist-fill' +
              (posture ? " df-" + k.toLowerCase() : "") +
              '" style="width:' + pct + '%"></span></span>' +
            '<span class="dist-count">' + count + "</span>" +
            '<span class="dist-pct">' + pct + "%</span>" +
          "</div>"
        );
      })
      .join("");
  }

  async function loadDatasetSettings() {
    try {
      const res = await fetch(DATASET_SETTINGS_URL);
      if (!res.ok) return;
      D().settings = await res.json();
    } catch (_) {
      D().settings = null;
    }
    const max = D().settings && D().settings.maximum_target_samples;
    const note = $("#datasetMaxNote");
    if (typeof max === "number") {
      const input = $("#datasetTargetInput");
      input.max = String(max);
      note.textContent = "Backend maximum: " + max + ". Your exact input is never changed \u2014 requests above the maximum are rejected.";
    } else {
      note.textContent = "";
    }
  }

  function datasetShowError(msg) {
    D().error = msg;
    renderDataset();
  }

  function datasetClearError() {
    D().error = null;
  }

  function readDatasetTarget() {
    const raw = $("#datasetTargetInput").value.trim();
    if (!raw) return { error: "Enter the number of successful experiments first." };
    if (!/^\d+$/.test(raw)) {
      return { error: "Experiment count must be a positive integer (e.g. 2, 50, 500)." };
    }
    const n = Number(raw);
    if (n < 1) {
      return { error: "Experiment count must be at least 1." };
    }
    const max = D().settings && D().settings.maximum_target_samples;
    if (typeof max === "number" && n > max) {
      return { error: "Experiment count " + n + " exceeds the backend maximum of " + max + "." };
    }
    return { value: n };
  }

  async function startDatasetRun() {
    const d = D();
    if (d.busy) return;

    const parsed = readDatasetTarget();
    if (parsed.error) {
      datasetShowError(parsed.error);
      return;
    }

    d.busy = true;
    datasetClearError();
    renderDataset();

    let res;
    try {
      res = await fetch(DATASETS_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_samples: parsed.value }),
      });
    } catch (_) {
      datasetShowError("Unable to reach the IPsec testbed controller. No run was created.");
      d.busy = false;
      renderDataset();
      return;
    }

    let status = null;
    try {
      status = await res.json();
    } catch (_) {
      status = null;
    }

    d.busy = false;

    if (res.status === 201 && status && status.dataset_run_id) {
      d.activeRunId = status.dataset_run_id;
      d.status = status;
      d.results = null;
      renderDataset();
      startDatasetPolling();
      return;
    }

    const detail = await readDetail(res);
    if (res.status === 409) {
      datasetShowError(
        detail || "Another automated run or a manual experiment is already using the testbed."
      );
    } else if (res.status === 422) {
      datasetShowError(
        detail || "The experiment count was rejected. It must be a positive integer within the backend maximum."
      );
    } else if (res.status === 404) {
      datasetShowError(detail || "The automated run endpoint was not found.");
    } else {
      datasetShowError(detail || "The controller rejected the automated run request. No run was created.");
    }
    renderDataset();
  }

  function stopDatasetPolling() {
    const d = D();
    d.pollToken += 1;
    if (d.pollTimer != null) {
      clearTimeout(d.pollTimer);
      d.pollTimer = null;
    }
  }

  async function fetchDatasetResults() {
    const d = D();
    if (!d.activeRunId) return null;
    try {
      const res = await fetch(DATASETS_URL + "/" + encodeURIComponent(d.activeRunId) + "/results");
      if (!res.ok) return null;
      const data = await res.json();
      d.results = data;
      renderStats();
      renderDataset();
      return data;
    } catch (_) {
      return null;
    }
  }

  async function pollDatasetStatus(token) {
    const d = D();
    if (token !== d.pollToken) return;
    if (!d.activeRunId) return;

    let res;
    try {
      res = await fetch(DATASETS_URL + "/" + encodeURIComponent(d.activeRunId));
    } catch (_) {
      if (token !== d.pollToken) return;
      datasetShowError("Lost connection to the controller while monitoring the automated run. Polling stopped.");
      stopDatasetPolling();
      return;
    }

    let status = null;
    try {
      status = await res.json();
    } catch (_) {
      status = null;
    }

    if (token !== d.pollToken) return;

    if (res.status === 404) {
      datasetShowError("Automated run not found: " + d.activeRunId + ". It may have been removed.");
      stopDatasetPolling();
      return;
    }
    if (!res.ok) {
      datasetShowError("The controller reported an error while monitoring the automated run. Polling stopped.");
      stopDatasetPolling();
      return;
    }
    if (!status || !status.status) {
      datasetShowError("The controller returned an unexpected response for the automated run. Polling stopped.");
      stopDatasetPolling();
      return;
    }

    d.status = status;
    datasetClearError();
    renderDataset();

    const statusName = status.status;

    if (statusName === "COMPLETED") {
      // Status COMPLETED is set before finalization.json is written; give the
      // finalizer a short grace window so results reflect finished artifacts.
      const fin = status.finalization;
      const done = fin && fin.status === "COMPLETED";
      if (!done) {
        let grace = 0;
        const finalizeTick = async function () {
          if (token !== d.pollToken) return;
          let finalized = false;
          try {
            const fres = await fetch(DATASETS_URL + "/" + encodeURIComponent(d.activeRunId));
            if (fres.ok) {
              const fdata = await fres.json();
              if (fdata && fdata.finalization && fdata.finalization.status === "COMPLETED") {
                d.status = fdata;
                renderDataset();
                finalized = true;
              }
            }
          } catch (_) {
            /* keep trying within the grace window */
          }
          if (token !== d.pollToken) return;
          if (finalized) {
            stopDatasetPolling();
            await fetchDatasetResults();
            return;
          }
          grace += 1;
          if (grace < FINALIZE_GRACE_POLLS) {
            d.pollTimer = setTimeout(finalizeTick, FINALIZE_GRACE_INTERVAL);
          } else {
            stopDatasetPolling();
            await fetchDatasetResults();
          }
        };
        d.pollTimer = setTimeout(finalizeTick, FINALIZE_GRACE_INTERVAL);
        return;
      }
      stopDatasetPolling();
      await fetchDatasetResults();
      return;
    }

    if (statusName === "FAILED" || statusName === "PAUSED") {
      stopDatasetPolling();
      return;
    }

    // CREATED / RUNNING -> poll again.
    d.pollTimer = setTimeout(function () { pollDatasetStatus(token); }, DATASET_POLL_INTERVAL);
  }

  function startDatasetPolling() {
    const d = D();
    stopDatasetPolling();
    const token = d.pollToken;
    d.pollTimer = setTimeout(function () {
      pollDatasetStatus(token);
    }, DATASET_POLL_INTERVAL);
  }

  async function resumeDatasetRun() {
    const d = D();
    if (!d.activeRunId || d.busy) return;

    d.busy = true;
    datasetClearError();
    renderDataset();

    let res;
    try {
      res = await fetch(DATASETS_URL + "/" + encodeURIComponent(d.activeRunId) + "/resume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
    } catch (_) {
      datasetShowError("Unable to reach the controller to resume the automated run.");
      d.busy = false;
      renderDataset();
      return;
    }

    const detail = await readDetail(res);
    d.busy = false;

    if (res.ok) {
      let status = null;
      try {
        status = await res.json();
      } catch (_) { /* payload optional */ }
      if (status && status.dataset_run_id) {
        d.status = status;
        renderDataset();
        startDatasetPolling();
        return;
      }
      stopDatasetPolling();
      return;
    }

    if (res.status === 409) {
      datasetShowError(detail || "The automated run cannot be resumed right now.");
    } else if (res.status === 400) {
      datasetShowError(detail || "The run's plan changed and cannot be resumed safely.");
    } else if (res.status === 404) {
      datasetShowError(detail || "Automated run not found.");
    } else {
      datasetShowError(detail || "The controller could not resume the automated run.");
    }
    renderDataset();
  }

  function downloadDataset() {
    const d = D();
    if (!d.activeRunId) return;
    const url =
      DATASETS_URL + "/" + encodeURIComponent(d.activeRunId) + "/download";
    // Same-origin anchor navigation: the server answers with attachment
    // Content-Disposition, so the browser saves the ZIP instead of navigating.
    const a = document.createElement("a");
    a.href = url;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  /* ---------- Dataset events ---------- */

  function bindDatasetEvents() {
    $("#datasetGenerateBtn").addEventListener("click", startDatasetRun);
    $("#datasetStatus").addEventListener("click", function (event) {
      if (event.target && event.target.id === "datasetResumeBtn") {
        resumeDatasetRun();
      } else if (event.target && event.target.id === "datasetDownloadBtn") {
        downloadDataset();
      }
    });
  }

  /* ---------- Events ---------- */

  function bindEvents() {
    bindDatasetEvents();

    $("#pfsSwitch").addEventListener("click", function () {
      if (state.running) return;
      state.pfs = !state.pfs;
      $("#pfsSwitch").classList.toggle("on", state.pfs);
      $("#pfsSwitch").setAttribute("aria-checked", String(state.pfs));
      updateSummary();
    });

    $("#espEncryption").addEventListener("change", function () {
      applyEspIntegrityState();
      updateSummary();
    });

    ["#ikeEncryption", "#ikeIntegrity", "#ikeDh", "#espDh"].forEach(function (sel) {
      $(sel).addEventListener("change", updateSummary);
    });

    $("#trafficProfile").addEventListener("change", updateSummary);
    $("#trafficDuration").addEventListener("input", updateSummary);

    $("#runBtn").addEventListener("click", runExperiment);
  }

  /* ---------- Init ---------- */

  async function init() {
    bindEvents();
    checkHealth();
    healthTimer = setInterval(checkHealth, 15000);
    await loadConfigurations();
    await loadDatasetSettings();
    renderDataset();
    renderStats();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();