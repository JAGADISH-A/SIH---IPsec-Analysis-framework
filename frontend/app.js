(() => {
  "use strict";

  const CONFIGS_URL = "/experiments/configurations";
  const EXPERIMENTS_URL = "/experiments";
  const HEALTH_URL = "/health";
  const POLL_INTERVAL = 800;

  const ENCRYPTION_LABELS = {
    aes128: "AES-128",
    aes256: "AES-256",
    aes128gcm16: "AES-128-GCM",
    aes256gcm16: "AES-256-GCM",
    aes128cbc: "AES-128-CBC",
    aes256cbc: "AES-256-CBC",
  };
  const INTEGRITY_LABELS = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
  const DH_LABELS = { modp2048: "MODP2048", modp3072: "MODP3072", modp4096: "MODP4096" };
  const MODE_LABELS = { tunnel: "Tunnel", transport: "Transport" };
  const FAMILY_LABELS = { ipv4: "IPv4", ipv6: "IPv6" };
  const IKE_VERSION_LABELS = { 1: "IKEv1", 2: "IKEv2" };

  const GCM_CIPHERS = ["aes128gcm16", "aes256gcm16"];

  const FALLBACK = {
    modes: ["tunnel", "transport"],
    address_families: ["ipv4", "ipv6"],
    ike: {
      versions: ["1", "2"],
      encryption: ["aes128", "aes256"],
      integrity: ["sha256", "sha384", "sha512"],
      dh_groups: ["modp2048", "modp3072", "modp4096"],
    },
    esp: {
      encryption: ["aes128gcm16", "aes256gcm16", "aes128cbc", "aes256cbc"],
      integrity: ["sha256", "sha384", "sha512"],
      dh_groups: ["modp2048", "modp3072", "modp4096"],
    },
  };

  let state = {
    mode: "tunnel",
    family: "ipv4",
    pfs: true,
    running: false,
    lastPayload: null,
  };

  let healthTimer = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  function show(el) { el.classList.remove("is-hidden"); }
  function hide(el) { el.classList.add("is-hidden"); }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function isGcm(cipher) {
    return GCM_CIPHERS.indexOf(cipher) !== -1;
  }

  function label(key) {
    return ENCRYPTION_LABELS[key] || INTEGRITY_LABELS[key] || DH_LABELS[key] || key;
  }

  function fillSelect(sel, options, labelMap, defaultVal) {
    sel.innerHTML = "";
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

  /* ---------- Payload & configuration ---------- */

  function getPayload() {
    const espEnc = $("#espEncryption").value;
    const gcm = isGcm(espEnc);

    return {
      mode: state.mode,
      address_family: state.family,
      ike: {
        version: Number($("#ikeVersion").value),
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
    };
  }

  function applyEspIntegrityState() {
    const gcm = isGcm($("#espEncryption").value);
    const sel = $("#espIntegrity");
    const note = $("#espIntegrityNote");

    sel.disabled = gcm;
    $("#espIntegrityField").classList.toggle("is-muted", gcm);
    note.classList.toggle("is-hidden", !gcm);

    if (!sel.value) {
      sel.value = "sha256";
    }
  }

  /* ---------- Key/value rows ---------- */

  function keysValues(p) {
    return [
      ["Mode", MODE_LABELS[p.mode] || p.mode, false],
      ["Address Family", FAMILY_LABELS[p.address_family] || p.address_family, false],
      ["IKE Version", "IKEv" + p.ike.version, false],
      ["IKE Encryption", label(p.ike.encryption), false],
      ["IKE Integrity", label(p.ike.integrity), false],
      ["DH Group", label(p.ike.dh_group), false],
      ["ESP Encryption", label(p.esp.encryption), false],
      ["ESP Integrity", p.esp.integrity ? label(p.esp.integrity) : "Not applicable", !p.esp.integrity],
      ["PFS", p.esp.pfs ? "Enabled" : "Disabled", false],
    ];
  }

  function keyValueRowsHtml(p, base) {
    return keysValues(p)
      .map(function (kv) {
        return (
          '<div class="' + base + '-row">' +
            '<span class="' + base + '-key">' + kv[0] + "</span>" +
            '<span class="' + base + "-val" + (kv[2] ? " na" : "") + '">' + kv[1] + "</span>" +
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
    $("#flowSub").textContent =
      mode === "tunnel" ? "Tunnel mode \u2014 network-to-network" : "Transport mode \u2014 host-to-host";

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

  /* ---------- Progress (job lifecycle) ---------- */

  function setJobState(status) {
    const labels = {
      QUEUED: "Queued",
      RUNNING: "Running\u2026",
      COMPLETED: "Completed",
      FAILED: "Failed",
    };
    const el = $("#jobStateLabel");
    el.className = "job-state st-" + String(status || "").toLowerCase();
    el.textContent = labels[status] || String(status || "");
  }

  function setChip(chip, mode) {
    chip.classList.remove("active", "done", "fail");
    if (mode) {
      chip.classList.add(mode);
    }
  }

  function stageLabel(stage) {
    const map = {
      QUEUED: "Queued",
      RUNNING: "Running",
      CONFIGURATION: "Configuration",
      EXPERIMENT: "Experiment run",
      COMPLETED: "Completed",
    };
    return map[stage] || stage || "";
  }

  function paintProgress(status, stage) {
    const chQ = $("#chQueued");
    const chR = $("#chRunning");
    const chC = $("#chCompleted");
    const chF = $("#chFailed");

    switch (status) {
      case "QUEUED":
        setChip(chQ, "active");
        setChip(chR, "");
        setChip(chC, "");
        setChip(chF, "");
        $("#stageCaption").textContent = "Waiting for the testbed slot to become available.";
        break;
      case "RUNNING":
        setChip(chQ, "done");
        setChip(chR, "active");
        setChip(chC, "");
        setChip(chF, "");
        $("#stageCaption").textContent = "The controller is applying the selected configuration to the testbed.";
        break;
      case "COMPLETED":
        setChip(chQ, "done");
        setChip(chR, "done");
        setChip(chC, "done");
        setChip(chF, "");
        $("#stageCaption").textContent = "The controller has finished the experiment.";
        break;
      case "FAILED": {
        const st = stageLabel(stage);
        setChip(chQ, "done");
        setChip(chR, "done");
        setChip(chC, "");
        setChip(chF, "fail");
        $("#stageCaption").textContent = st
          ? "Failed during " + st.toLowerCase() + "."
          : "The controller stopped the experiment.";
        break;
      }
      default:
        setChip(chQ, "active");
        setChip(chR, "");
        setChip(chC, "");
        setChip(chF, "");
        $("#stageCaption").textContent = "";
    }
  }

  /* ---------- Results ---------- */

  function resetResultStates() {
    hide($("#emptyState"));
    hide($("#passState"));
    hide($("#failState"));
    hide($("#rejectState"));
    show($("#progressWrap"));
  }

  function renderPass(result) {
    hide($("#progressWrap"));

    const ip = result.ipsec || {};
    const con = result.connectivity || {};

    $("#mIke").textContent = ip.ike_sa || "\u2014";
    $("#mChild").textContent = ip.child_sa || "\u2014";
    $("#mMode").textContent = ip.mode || "\u2014";
    $("#mLoss").textContent = con.packet_loss != null ? Math.round(con.packet_loss) + "%" : "\u2014";

    $("#passConfig").innerHTML = state.lastPayload ? keyValueRowsHtml(state.lastPayload, "conf") : "";

    show($("#passState"));
    paintFlow(["result"], ["configure", "run", "verify"]);
  }

  function finalizeFail(stage, message) {
    hide($("#progressWrap"));

    const stg = stage || "the controller";
    $("#failStage").innerHTML = "Failed at <b>" + stg + "</b>";
    $("#failMessage").textContent = message || "The experiment could not be completed.";

    $("#failConfig").innerHTML = state.lastPayload ? keyValueRowsHtml(state.lastPayload, "conf") : "";

    show($("#failState"));
    paintFlow(["result"], ["configure", "run", "verify"]);
  }

  function finalizeReject(message) {
    hide($("#progressWrap"));

    $("#rejectMessage").textContent = message || "The experiment could not be started.";

    show($("#rejectState"));
    paintFlow(["configure"], []);
  }

  /* ---------- Error classification (HTTP 4xx/5xx during submission) ---------- */

  function classifyError(status, detail) {
    const d = String(detail || "").toLowerCase();

    if (status === 400) {
      return { stage: "Configuration", message: detail || "The selected configuration is not supported by the testbed." };
    }
    if (/config/.test(d)) {
      return { stage: "Configuration", message: detail };
    }
    if (/deploy|topology|container|docker|clab/.test(d)) {
      return { stage: "Deployment", message: detail };
    }
    if (/ike|established|firewall|keying|auth/.test(d)) {
      return { stage: "IKE", message: detail };
    }
    if (/child|installed/.test(d)) {
      return { stage: "CHILD SA", message: detail };
    }
    if (/ping|packet loss|connect/.test(d)) {
      return { stage: "Connectivity", message: detail };
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

  /* ---------- Run experiment ---------- */

  function setRunningUI(on) {
    const runBtn = $("#runBtn");
    const runLabel = $("#runLabel");
    runBtn.disabled = on;
    runBtn.classList.toggle("is-running", on);
    runLabel.textContent = on ? "Running\u2026" : "Run Experiment";
    $("#configCard").classList.toggle("is-disabled", on);
  }

  async function runExperiment() {
    if (state.running) return;

    state.running = true;
    setRunningUI(true);

    resetResultStates();
    paintFlow(["run"], ["configure"]);
    state.lastPayload = getPayload();

    paintProgress("QUEUED", "");
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
          finalizeReject(detail || "Another experiment is already running.");
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

        if (job.status === "COMPLETED") {
          const result = job.result;

          if (result && result.status === "PASS") {
            renderPass(result);
          } else {
            const con = (result && result.connectivity) || {};
            const loss = con.packet_loss;
            const msg = loss != null
              ? "Connectivity verification failed: " + Math.round(loss) + "% packet loss."
              : "The experiment completed but did not report a PASS result.";
            finalizeFail("Connectivity", msg);
          }
          return;
        }

        if (job.status === "FAILED") {
          const stage =
            job.stage === "CONFIGURATION" ? "Configuration" :
            job.stage === "EXPERIMENT" ? "Experiment" : "";
          finalizeFail(stage, job.error || "The experiment could not be completed.");
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

  /* ---------- Option loading ---------- */

  function seedConfigOptions() {
    fillSelect($("#ikeVersion"), FALLBACK.ike.versions, IKE_VERSION_LABELS, "2");
    fillSelect($("#ikeEncryption"), FALLBACK.ike.encryption, ENCRYPTION_LABELS, "aes256");
    fillSelect($("#ikeIntegrity"), FALLBACK.ike.integrity, INTEGRITY_LABELS, "sha256");
    fillSelect($("#ikeDh"), FALLBACK.ike.dh_groups, DH_LABELS, "modp2048");
    fillSelect($("#espEncryption"), FALLBACK.esp.encryption, ENCRYPTION_LABELS, "aes256gcm16");
    fillSelect($("#espIntegrity"), FALLBACK.esp.integrity, INTEGRITY_LABELS, "sha256");
    fillSelect($("#espDh"), FALLBACK.esp.dh_groups, DH_LABELS, "modp2048");
    applyEspIntegrityState();
  }

  async function loadConfigurations() {
    let data = null;
    try {
      const res = await fetch(CONFIGS_URL);
      if (res.ok) {
        data = await res.json();
      }
    } catch (_) {}

    const cfg = data || FALLBACK;
    const ike = cfg.ike || FALLBACK.ike;
    const esp = cfg.esp || FALLBACK.esp;

    const versions = ike.versions && ike.versions.length ? ike.versions : FALLBACK.ike.versions;

    fillSelect($("#ikeVersion"), versions, IKE_VERSION_LABELS, "2");
    fillSelect($("#ikeEncryption"), ike.encryption || FALLBACK.ike.encryption, ENCRYPTION_LABELS, "aes256");
    fillSelect($("#ikeIntegrity"), ike.integrity || FALLBACK.ike.integrity, INTEGRITY_LABELS, "sha256");
    fillSelect($("#ikeDh"), ike.dh_groups || FALLBACK.ike.dh_groups, DH_LABELS, "modp2048");
    fillSelect($("#espEncryption"), esp.encryption || FALLBACK.esp.encryption, ENCRYPTION_LABELS, "aes256gcm16");
    fillSelect($("#espIntegrity"), esp.integrity || FALLBACK.esp.integrity, INTEGRITY_LABELS, "sha256");
    fillSelect($("#espDh"), esp.dh_groups || FALLBACK.esp.dh_groups, DH_LABELS, "modp2048");

    applyEspIntegrityState();
    updateSummary();
  }

  /* ---------- Events ---------- */

  function bindSegmented(containerSel, attr, refresh) {
    $$(containerSel + " .seg-option").forEach(function (btn) {
      btn.addEventListener("click", function () {
        if (state.running) return;
        $$(containerSel + " .seg-option").forEach(function (b) {
          b.classList.remove("active");
          b.setAttribute("aria-checked", "false");
        });
        btn.classList.add("active");
        btn.setAttribute("aria-checked", "true");
        if (attr === "mode") {
          state.mode = btn.dataset.mode;
          buildFlow();
        } else {
          state.family = btn.dataset.family;
        }
        refresh();
      });
    });
  }

  function bindEvents() {
    bindSegmented("#modeSegmented", "mode", updateSummary);
    bindSegmented("#familySegmented", "family", updateSummary);

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

    ["#ikeVersion", "#ikeEncryption", "#ikeIntegrity", "#ikeDh", "#espDh"].forEach(function (sel) {
      $(sel).addEventListener("change", updateSummary);
    });

    $("#runBtn").addEventListener("click", runExperiment);
  }

  /* ---------- Init ---------- */

  function init() {
    seedConfigOptions();
    updateSummary();
    buildFlow();
    bindEvents();
    checkHealth();
    healthTimer = setInterval(checkHealth, 15000);
    loadConfigurations();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();