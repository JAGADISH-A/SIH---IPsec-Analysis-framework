(() => {
  "use strict";

  const CONFIGS_URL = "/experiments/configurations";
  const EXPERIMENTS_URL = "/experiments";
  const HEALTH_URL = "/health";

  const ENCRYPTION_LABELS = {
    aes128: "AES-128",
    aes256: "AES-256",
    aes128gcm16: "AES-128-GCM",
    aes256gcm16: "AES-256-GCM",
  };
  const INTEGRITY_LABELS = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
  const DH_LABELS = { modp2048: "MODP-2048", modp3072: "MODP-3072", modp4096: "MODP-4096" };
  const MODE_LABELS = { tunnel: "Tunnel Mode", transport: "Transport Mode" };

  const PROGRESS_STEPS = [
    "Deploying testbed\u2026",
    "Applying IPsec configuration\u2026",
    "Establishing security association\u2026",
    "Testing connectivity\u2026",
    "Verifying IPsec\u2026",
  ];

  const FALLBACK = {
    modes: ["tunnel", "transport"],
    ike: { encryption: ["aes128", "aes256"], integrity: ["sha256", "sha384", "sha512"], dh_groups: ["modp2048", "modp3072", "modp4096"] },
    esp: { encryption: ["aes128gcm16", "aes256gcm16"], dh_groups: ["modp2048", "modp3072", "modp4096"] },
  };

  let state = {
    mode: "tunnel",
    pfs: true,
    running: false,
    lastPayload: null,
  };

  let progressEls = [];
  let progressTimer = null;
  let healthTimer = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  function show(el) { el.classList.remove("is-hidden"); }
  function hide(el) { el.classList.add("is-hidden"); }

  /* ---------- SVG icons ---------- */

  function checkSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
  }

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

  function doubleArrowSvg() {
    return '<svg class="arrow double" viewBox="0 0 24 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 1L23 6l-5 5M6 1L1 6l5 5"/><path d="M1 6h22"/></svg>';
  }

  /* ---------- Helpers ---------- */

  function val(key) {
    const map = Object.assign({}, ENCRYPTION_LABELS, INTEGRITY_LABELS, DH_LABELS);
    return map[key] || key;
  }

  function fillSelect(sel, options, labelMap, defaultVal) {
    sel.innerHTML = "";
    for (const v of options) {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = labelMap[v] || v;
      sel.appendChild(opt);
    }
    if (defaultVal && options.includes(defaultVal)) {
      sel.value = defaultVal;
    }
  }

  function getPayload() {
    return {
      mode: state.mode,
      ike: {
        version: 2,
        encryption: $("#ikeEncryption").value,
        integrity: $("#ikeIntegrity").value,
        dh_group: $("#ikeDh").value,
      },
      esp: {
        encryption: $("#espEncryption").value,
        dh_group: $("#espDh").value,
        pfs: state.pfs,
      },
    };
  }

  /* ---------- Flow painting ---------- */

  function paintFlow(activeKeys, doneKeys) {
    $$(".flow-step").forEach((el) => {
      const k = el.dataset.step;
      el.classList.toggle("active", activeKeys.includes(k));
      el.classList.toggle("done", doneKeys.includes(k));
    });
  }

  /* ---------- Summary ---------- */

  function updateSummary() {
    const p = getPayload();
    const ike = [val(p.ike.encryption), val(p.ike.integrity), val(p.ike.dh_group)].join(" \u00b7 ");
    const esp = [val(p.esp.encryption), p.esp.pfs ? "PFS Enabled" : "PFS Disabled"].join(" \u00b7 ");
    const lines = [
      "IKEv2 \u2022 " + ike,
      "ESP \u2022 " + esp,
      MODE_LABELS[p.mode],
    ];
    $("#summaryLines").innerHTML = lines.map((l) => '<div class="summary-line">' + l + "</div>").join("");
  }

  /* ---------- Flow diagram ---------- */

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

  /* ---------- Progress ---------- */

  function showProgress() {
    $("#progressList").innerHTML = "";
    progressEls = [];

    PROGRESS_STEPS.forEach((label) => {
      const el = document.createElement("div");
      el.className = "progress-step";
      el.innerHTML = '<span class="step-ico">' + checkSvg() + '</span><span>' + label + "</span>";
      $("#progressList").appendChild(el);
      progressEls.push(el);
    });

    progressEls[0].classList.add("active");
    $("#progressHead").textContent = PROGRESS_STEPS[0];

    let idx = 0;
    progressTimer = setInterval(() => {
      progressEls[idx].classList.remove("active");
      progressEls[idx].classList.add("done");
      idx++;
      if (idx < progressEls.length) {
        progressEls[idx].classList.add("active");
        $("#progressHead").textContent = PROGRESS_STEPS[idx];
      } else {
        clearInterval(progressTimer);
        progressTimer = null;
      }
    }, 2500);
  }

  function finishProgress() {
    if (progressTimer) {
      clearInterval(progressTimer);
      progressTimer = null;
    }
    progressEls.forEach((el) => {
      el.classList.remove("active");
      el.classList.add("done");
    });
    if (progressEls.length) {
      $("#progressHead").textContent = "Analysis complete";
    }
  }

  /* ---------- Results ---------- */

  function renderPass(result) {
    const ip = result.ipsec || {};
    const con = result.connectivity || {};

    $("#mIke").textContent = ip.ike_sa || "\u2014";
    $("#mChild").textContent = ip.child_sa || "\u2014";
    $("#mMode").textContent = ip.mode || "\u2014";
    $("#mLoss").textContent = con.packet_loss != null ? Math.round(con.packet_loss) + "%" : "\u2014";

    show($("#passState"));
    paintFlow(["result"], ["configure", "run", "verify"]);
  }

  function renderFail(stage, message) {
    const stg = stage || "Deployment";
    const msg = message || "The experiment could not be completed.";

    $("#failStage").innerHTML = "Failed at <b>" + stg + "</b>";
    $("#failMessage").textContent = msg;

    show($("#failState"));
    paintFlow(["result"], ["configure", "run", "verify"]);
  }

  function updateDetails(result) {
    const p = state.lastPayload || {};
    const ike = (result && result.ike) || p.ike || {};
    const esp = (result && result.esp) || p.esp || {};
    const con = (result && result.connectivity) || {};
    const mode = (result && result.mode) || p.mode || "";

    $("#dtMode").textContent = MODE_LABELS[mode] || "\u2014";
    $("#dtIke").textContent =
      ike.encryption ? [val(ike.encryption), val(ike.integrity), val(ike.dh_group)].join(" \u00b7 ") : "\u2014";
    $("#dtEsp").textContent =
      esp.encryption ? [val(esp.encryption), val(esp.dh_group)].join(" \u00b7 ") : "\u2014";
    $("#dtPfs").textContent = esp.pfs != null ? (esp.pfs ? "Enabled" : "Disabled") : "\u2014";

    if (con.packet_loss != null) {
      $("#dtConn").textContent = Math.round(con.packet_loss) + "% packet loss";
    } else {
      $("#dtConn").textContent = "\u2014";
    }

    if (result && result.status) {
      $("#dtResult").textContent = result.status;
      $("#dtResult").className = "detail-value " + (result.status === "PASS" ? "pass" : "fail");
    } else {
      $("#dtResult").textContent = "\u2014";
      $("#dtResult").className = "detail-value";
    }
  }

  /* ---------- Error classification ---------- */

  function classifyError(status, detail) {
    const d = String(detail || "").toLowerCase();

    if (status === 400 || /(unsupported|invalid|not a valid|config)/.test(d)) {
      return { stage: "Configuration", message: detail || "The selected configuration is not supported by the testbed." };
    }
    if (/child|installed/.test(d)) {
      return { stage: "CHILD SA", message: detail || "The CHILD security association could not be installed." };
    }
    if (/ike|established|firewall|keying|auth/.test(d)) {
      return { stage: "IKE", message: detail || "The IKE security association could not be established." };
    }
    if (/ping|packet loss|connect|destination|no route|unreachable/.test(d)) {
      return { stage: "Connectivity", message: detail || "Traffic did not pass across the testbed." };
    }
    if (/deploy|topology|container|swanctl|docker|clab|image|permission|sudo/.test(d)) {
      return { stage: "Deployment", message: detail || "The testbed could not be deployed or configured." };
    }
    return { stage: "Deployment", message: detail || "The experiment could not be completed." };
  }

  /* ---------- Run experiment ---------- */

  async function runExperiment() {
    if (state.running) return;
    state.running = true;

    const runBtn = $("#runBtn");
    const runLabel = $("#runLabel");
    runBtn.disabled = true;
    runBtn.classList.add("is-running");
    runLabel.textContent = "Running\u2026";
    $("#configCard").classList.add("is-disabled");

    hide($("#emptyState"));
    hide($("#passState"));
    hide($("#failState"));
    show($("#progressWrap"));
    paintFlow(["run", "verify"], ["configure"]);

    state.lastPayload = getPayload();
    showProgress();

    try {
      const res = await fetch(EXPERIMENTS_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(state.lastPayload),
      });

      let result;
      if (!res.ok) {
        let detail = "";
        try {
          const j = await res.json();
          detail = j.detail || "";
        } catch (_) {}
        const c = classifyError(res.status, detail);
        result = { status: "FAIL", _error: true, stage: c.stage, message: c.message };
      } else {
        result = await res.json();
      }

      finishProgress();

      if (result.status === "PASS") {
        renderPass(result);
      } else {
        if (result._error) {
          renderFail(result.stage, result.message);
        } else {
          renderFail(
            "Connectivity",
            "Connectivity check failed: " +
              Math.round((result.connectivity || {}).packet_loss || 0) +
              "% packet loss detected."
          );
        }
      }

      updateDetails(result);
    } catch (err) {
      finishProgress();

      let stage, message;
      if (err.name === "TypeError") {
        stage = "Configuration";
        message = "Unable to reach the testbed controller. Please verify that the backend is running.";
      } else {
        stage = "Deployment";
        message = err.message || "The experiment could not be completed.";
      }

      renderFail(stage, message);
      updateDetails(null);
    } finally {
      state.running = false;
      runBtn.disabled = false;
      runBtn.classList.remove("is-running");
      runLabel.textContent = "RUN EXPERIMENT";
      $("#configCard").classList.remove("is-disabled");
    }
  }

  /* ---------- Health ---------- */

  async function checkHealth() {
    try {
      const res = await fetch(HEALTH_URL);
      const data = await res.json();
      const ok = data.status === "ok";
      $("#statusPill").classList.toggle("is-offline", !ok);
      $("#statusText").textContent = ok ? "Testbed Ready" : "Testbed Unavailable";
    } catch (_) {
      $("#statusPill").classList.add("is-offline");
      $("#statusText").textContent = "Controller Offline";
    }
  }

  /* ---------- Init ---------- */

  async function loadConfigurations() {
    let data;
    try {
      const res = await fetch(CONFIGS_URL);
      data = await res.json();
    } catch (_) {
      data = FALLBACK;
    }

    const ike = data.ike || FALLBACK.ike;
    const esp = data.esp || FALLBACK.esp;

    fillSelect($("#ikeEncryption"), ike.encryption, ENCRYPTION_LABELS, "aes256");
    fillSelect($("#ikeIntegrity"), ike.integrity, INTEGRITY_LABELS, "sha256");
    fillSelect($("#ikeDh"), ike.dh_groups, DH_LABELS, "modp2048");
    fillSelect($("#espEncryption"), esp.encryption, ENCRYPTION_LABELS, "aes256gcm16");
    fillSelect($("#espDh"), esp.dh_groups, DH_LABELS, "modp2048");
  }

  function bindEvents() {
    $$(".seg-option").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".seg-option").forEach((b) => {
          b.classList.remove("active");
          b.setAttribute("aria-checked", "false");
        });
        btn.classList.add("active");
        btn.setAttribute("aria-checked", "true");
        state.mode = btn.dataset.mode;
        updateSummary();
        buildFlow();
      });
    });

    $("#pfsSwitch").addEventListener("click", () => {
      state.pfs = !state.pfs;
      $("#pfsSwitch").classList.toggle("on", state.pfs);
      $("#pfsSwitch").setAttribute("aria-checked", String(state.pfs));
      updateSummary();
    });

    const watcher = () => updateSummary();
    ["#ikeEncryption", "#ikeIntegrity", "#ikeDh", "#espEncryption", "#espDh"].forEach((sel) => {
      $(sel).addEventListener("change", watcher);
    });

    $("#runBtn").addEventListener("click", runExperiment);
  }

  function init() {
    loadConfigurations();
    updateSummary();
    buildFlow();
    bindEvents();
    checkHealth();
    healthTimer = setInterval(checkHealth, 15000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
