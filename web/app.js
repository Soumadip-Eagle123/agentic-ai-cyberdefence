(() => {
  const state = {
    catalog: null,
    simulation: null,
    selectedLayer: 0,
    selectedDevice: null,
    selectedBucket: "observed_fact",
    chainPath: [],
    source: null,
    eventSource: null,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  async function request(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      body: options.body ? JSON.stringify(options.body) : options.body,
    });
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok) throw new Error(payload?.error || `Request failed (${response.status})`);
    return payload;
  }

  function showToast(message, type = "success") {
    const node = document.createElement("div");
    node.className = `toast ${type}`;
    node.textContent = message;
    $("#toast-region").append(node);
    setTimeout(() => node.remove(), 3900);
  }

  function addTerminalLine(message, type = "info") {
    const output = $("#terminal-output");
    const line = document.createElement("div");
    line.className = `terminal-line ${type}`;
    line.textContent = message;
    output.append(line);
    output.scrollTop = output.scrollHeight;
  }

  function nowClock() {
    const value = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date());
    $("#local-clock").textContent = `${value} UTC`;
  }

  function populateInputs() {
    const catalog = state.catalog;
    if (!catalog) return;
    const scenarioSelect = $("#scenario-select");
    scenarioSelect.innerHTML = `<option value="custom_attack">Custom attack</option>${catalog.scenarios.map((scenario) => `<option value="${escapeHtml(scenario)}">${escapeHtml(scenario.replaceAll("_", " "))}</option>`).join("")}`;
    const deviceOptions = catalog.devices.map((device) => `<option value="${escapeHtml(device.id)}">${escapeHtml(device.id)} · ${escapeHtml(device.zone)} · Tier ${device.tier}</option>`).join("");
    $("#attack-source").innerHTML = deviceOptions;
    $("#attack-target").innerHTML = deviceOptions;
    $("#chain-next-hop").innerHTML = deviceOptions;
    $("#attack-source").value = "office-ws";
    $("#attack-target").value = "radiology-ws";
    $("#chain-next-hop").value = "radiology-ws";
    renderHelp();
  }

  function renderChainSequence() {
    const path = state.chainPath || [];
    const names = path.map((deviceId) => {
      const device = state.catalog?.devices.find((item) => item.id === deviceId);
      return device?.id || deviceId;
    });
    $("#chain-sequence").innerHTML = names.length
      ? names.map((name, index) => `${index ? `<span class="chain-arrow">→</span>` : ""}<span class="chain-sequence-node">${index + 1}. ${escapeHtml(name)}<button type="button" data-remove-hop="${index}" aria-label="Remove ${escapeHtml(name)}">×</button></span>`).join("")
      : `<span class="chain-sequence-empty">Choose the first destination and add hops in order.</span>`;
    $$('[data-remove-hop]').forEach((button) => button.addEventListener("click", () => {
      const index = Number(button.dataset.removeHop);
      if (index === 0) {
        showToast("Change the attacker source in the source selector.", "error");
        return;
      }
      state.chainPath.splice(index);
      if (state.chainPath.length > 1) $("#attack-target").value = state.chainPath.at(-1);
      renderChainSequence();
    }));
  }

  function artMarkup(kind) {
    const art = {
      monitor: `<svg viewBox="0 0 50 42" aria-hidden="true"><rect class="art-screen" x="4" y="4" width="42" height="29" rx="2"/><path class="art-line" d="M7 19h7l3-8 4 17 4-12 3 4h4l3-8 3 7h5"/><path class="art-dim" d="M19 36h12M25 33v3"/><circle class="art-led" cx="41" cy="8" r="1.4"/></svg>`,
      controller: `<svg viewBox="0 0 50 42" aria-hidden="true"><rect class="art-body" x="10" y="3" width="30" height="36" rx="2"/><path class="art-dim" d="M15 8h19M15 24h19M15 33h19"/><circle class="art-led" cx="17" cy="15" r="2"/><circle class="art-led amber" cx="24" cy="15" r="2"/><circle class="art-led" cx="31" cy="15" r="2"/><path class="art-detail" d="M16 20h17M16 29h17"/></svg>`,
      server: `<svg viewBox="0 0 50 42" aria-hidden="true"><rect class="art-body" x="3" y="4" width="31" height="34" rx="2"/><path class="art-dim" d="M7 13h23M7 23h23M7 33h23"/><circle class="art-led" cx="10" cy="9" r="1.5"/><circle class="art-led" cx="10" cy="19" r="1.5"/><circle class="art-led" cx="10" cy="29" r="1.5"/><path class="art-detail" d="M37 14c0-3 3-4 5-2 2 2 0 5-2 7v10M37 29h7"/><path class="art-detail" d="M37 12h8"/></svg>`,
      radiology: `<svg viewBox="0 0 50 42" aria-hidden="true"><rect class="art-screen" x="3" y="4" width="42" height="27" rx="2"/><path class="art-dim" d="M24 8v17M24 10c-7-5-13 2-11 11 1 4 5 6 11 5M24 10c7-5 13 2 11 11-1 4-5 6-11 5"/><path class="art-detail" d="M20 34h9M24 31v3"/><circle class="art-led" cx="40" cy="8" r="1.3"/></svg>`,
      desktop: `<svg viewBox="0 0 50 42" aria-hidden="true"><rect class="art-screen" x="4" y="3" width="34" height="27" rx="2"/><path class="art-detail" d="M19 31v5M11 37h21"/><rect x="9" y="8" width="7" height="7" fill="#176b4e"/><rect x="18" y="8" width="7" height="7" fill="#247ca0"/><rect x="27" y="8" width="7" height="7" fill="#b9853e"/><path class="art-dim" d="M9 19h25M9 23h19"/><circle class="art-led" cx="34" cy="36" r="1.4"/></svg>`,
      database: `<svg viewBox="0 0 50 42" aria-hidden="true"><ellipse class="art-body" cx="21" cy="8" rx="15" ry="5"/><path class="art-detail" d="M6 8v25c0 3 7 6 15 6s15-3 15-6V8M6 16c0 3 7 5 15 5s15-2 15-5M6 25c0 3 7 5 15 5s15-2 15-5"/><path class="art-body" d="M36 22l7 3v6c0 5-3 8-7 10-4-2-7-5-7-10v-6z"/><path class="art-detail" d="M33 31l2 2 4-5"/><circle class="art-led" cx="14" cy="12" r="1"/></svg>`,
    };
    return art[kind] || art.database;
  }

  function deviceStatus(device, simulation) {
    if (!simulation?.active) return { label: "ONLINE · NORMAL", className: "" };
    const proposalAssets = simulation.proposal?.candidate_actions?.map((action) => action.target_asset) || [];
    const onPath = simulation.attack_path?.some(([from, to]) => from === device.id || to === device.id);
    const actionApplied = ["APPLIED", "ROLLED_BACK"].includes(simulation.enforcement?.status);
    const rolledBack = simulation.enforcement?.status === "ROLLED_BACK";
    if (rolledBack && proposalAssets.includes(device.id)) return { label: "ONLINE · RULES RESTORED", className: "" };
    if (device.tier === 1 && proposalAssets.includes(device.id)) {
      if (simulation.pending_approval) return { label: "REVIEW PAUSED · STREAM ACTIVE", className: "infected" };
      if (actionApplied && simulation.enforcement?.status === "APPLIED") return { label: "SURGICAL BLOCK · HL7 ACTIVE", className: "infected" };
      return { label: "TIER 1 · NEVER ISOLATED", className: "infected" };
    }
    if (device.tier === 3 && actionApplied && proposalAssets.includes(device.id) && simulation.proposal?.candidate_actions?.some((action) => action.target_asset === device.id && action.action_type === "COARSE_ISOLATION")) {
      return { label: "COARSE ISOLATION · SIMULATED", className: "isolated" };
    }
    if (proposalAssets.includes(device.id) && actionApplied) return { label: "NARROW BLOCK · WORKFLOW UP", className: "infected" };
    if (onPath) return { label: device.id === simulation.source ? "ATTACK ORIGIN · SIMULATED" : "ANOMALY UNDER REVIEW", className: "infected" };
    return { label: "ONLINE · NORMAL", className: "" };
  }

  function renderDevices() {
    const devices = state.catalog?.devices || [];
    const positions = {
      "icu-monitor-gw": ["2%", "15%"],
      "icu-controller": ["36%", "15%"],
      "lab-server": ["70%", "15%"],
      "office-ws": ["2%", "62%"],
      "radiology-ws": ["36%", "62%"],
      "ehr-core": ["70%", "62%"],
    };
    const simulation = state.simulation;
    $("#device-layer").innerHTML = devices.map((device) => {
      const [x, y] = positions[device.id];
      const status = deviceStatus(device, simulation);
      const tierClass = `tier-${device.tier === 1 ? "one" : device.tier === 2 ? "two" : "three"}`;
      const selected = state.selectedDevice === device.id ? " selected" : "";
      const classes = `device-node ${tierClass} ${status.className}${selected}`.trim();
      const safety = device.tier === 1
        ? `<div class="safety-strip"><span>${device.id === "icu-monitor-gw" ? "HL7 2575 ALWAYS ACTIVE" : "NO FULL ISOLATION"}</span><span>TIER 1</span></div>`
        : `<div class="safety-strip"><span>${escapeHtml(device.safety)}</span><span>T${device.tier}</span></div>`;
      return `<button class="${classes}" data-device="${escapeHtml(device.id)}" style="--x:${x};--y:${y}" aria-label="Inspect ${escapeHtml(device.id)}">
        <div class="node-head"><span class="device-art">${artMarkup(device.icon)}</span><span class="node-title-wrap"><span class="node-title">${escapeHtml(device.name)}</span><span class="node-id">${escapeHtml(device.id)}</span><span class="node-state">${escapeHtml(status.label)}</span></span><span class="node-tier">TIER ${device.tier}</span></div>
        <div class="node-details"><span class="node-ip">${escapeHtml(device.ip)}</span><span class="node-service">${escapeHtml(device.services[0])}</span></div>${safety}
      </button>`;
    }).join("");
    $$(".device-node").forEach((node) => node.addEventListener("click", () => inspectDevice(node.dataset.device)));
    $("#online-count").textContent = String(devices.length).padStart(2, "0");
  }

  function pathForWire(from, to) {
    const points = {
      "icu-monitor-gw": [165, 154], "icu-controller": [505, 154], "lab-server": [845, 154],
      "office-ws": [165, 394], "radiology-ws": [505, 394], "ehr-core": [845, 394],
    };
    const a = points[from];
    const b = points[to];
    if (!a || !b) return "";
    const dx = b[0] - a[0];
    const dy = b[1] - a[1];
    if (Math.abs(dy) < 30) return `M ${a[0]} ${a[1]} C ${a[0] + dx * .25} ${a[1] - 24}, ${a[0] + dx * .75} ${b[1] - 24}, ${b[0]} ${b[1]}`;
    const bend = dy > 0 ? 65 : -65;
    return `M ${a[0]} ${a[1]} C ${a[0] + dx * .16} ${a[1] + bend}, ${b[0] - dx * .16} ${b[1] - bend}, ${b[0]} ${b[1]}`;
  }

  function renderWires() {
    const svg = $("#wire-layer");
    const wires = state.catalog?.wires || [];
    const simulation = state.simulation;
    const paths = simulation?.attack_path || [];
    const content = [];
    wires.forEach((wire, index) => {
      const activeAttack = paths.some(([from, to]) => from === wire.from && to === wire.to);
      const actionTarget = simulation?.proposal?.candidate_actions?.some((action) => action.target_asset === wire.to || action.target_asset === wire.from);
      const isolated = simulation?.enforcement?.status === "APPLIED" && simulation?.proposal?.candidate_actions?.some((action) => action.action_type === "COARSE_ISOLATION" && (action.target_asset === wire.from || action.target_asset === wire.to));
      const type = activeAttack ? "attack" : isolated ? "isolated" : wire.kind === "clinical" ? "clinical" : "normal";
      const d = pathForWire(wire.from, wire.to);
      const midpoint = pathMidpoint(wire.from, wire.to);
      content.push(`<path class="wire-path ${type} ${activeAttack ? "clickable" : ""}" d="${d}" data-path="${activeAttack ? "attack" : "normal"}" data-wire="${index}"/>`);
      content.push(`<path class="wire-hit" d="${d}" data-path="${activeAttack ? "attack" : "normal"}" data-wire="${index}"/>`);
      if (activeAttack) content.push(`<text class="wire-caption attack-label" x="${midpoint[0]}" y="${midpoint[1] - 6}" text-anchor="middle" data-wire="${index}">ANOMALY / PIVOT</text>`);
      else if (wire.kind === "clinical") content.push(`<text class="wire-caption" x="${midpoint[0]}" y="${midpoint[1] - 5}" text-anchor="middle">${escapeHtml(wire.label)}</text>`);
      if (actionTarget && simulation?.enforcement?.status === "APPLIED" && wire.kind === "clinical") {
        content.push(`<circle cx="${midpoint[0]}" cy="${midpoint[1]}" r="4" fill="#09141e" stroke="#4be0a0" stroke-width="1.5"/>`);
      }
    });
    paths.forEach(([from, to], index) => {
      if (wires.some((wire) => wire.from === from && wire.to === to)) return;
      const d = pathForWire(from, to);
      const midpoint = pathMidpoint(from, to);
      const wireIndex = wires.length + index;
      content.push(`<path class="wire-path attack clickable" d="${d}" data-path="attack" data-wire="${wireIndex}"/>`);
      content.push(`<path class="wire-hit" d="${d}" data-path="attack" data-wire="${wireIndex}"/>`);
      content.push(`<text class="wire-caption attack-label" x="${midpoint[0]}" y="${midpoint[1] - 6}" text-anchor="middle" data-wire="${wireIndex}">ANOMALY / PIVOT</text>`);
    });
    if (simulation?.blocked_flows?.length) {
      const coords = { "icu-monitor-gw": [165, 154], "icu-controller": [505, 154], "lab-server": [845, 154], "office-ws": [165, 394], "radiology-ws": [505, 394], "ehr-core": [845, 394] };
      const actions = simulation.proposal?.candidate_actions?.filter((action) => action.blocked_flows?.length) || [];
      actions.forEach((action, index) => {
        const point = coords[action.target_asset];
        if (!point) return;
        const x = Math.min(970, point[0] + 100);
        const y = Math.max(20, point[1] - 33 - index * 15);
        content.push(`<path class="wire-path blocked" d="M ${point[0] + 25} ${point[1] - 17} L ${x} ${y}"/>`);
        content.push(`<text class="wire-block-mark" x="${x}" y="${y + 5}" text-anchor="middle">×</text>`);
        content.push(`<text class="wire-caption attack-label" x="${x + 8}" y="${y - 7}">SMB 445 BLOCKED</text>`);
      });
    }
    svg.innerHTML = content.join("");
    $$(".wire-hit", svg).forEach((path) => path.addEventListener("click", () => {
      if (path.dataset.path === "attack") showChainDetails();
    }));
    $$(".wire-caption.attack-label", svg).forEach((label) => label.addEventListener("click", showChainDetails));
  }

  function pathMidpoint(from, to) {
    const points = { "icu-monitor-gw": [165, 154], "icu-controller": [505, 154], "lab-server": [845, 154], "office-ws": [165, 394], "radiology-ws": [505, 394], "ehr-core": [845, 394] };
    const a = points[from] || [0, 0];
    const b = points[to] || [0, 0];
    return [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2];
  }

  function renderStepper() {
    const simulation = state.simulation;
    const order = state.catalog?.layer_order || [0, 1, 2, 3, 5, 4, 6];
    const short = { 0: "INGEST", 1: "ASSET", 2: "ML", 3: "ORCH", 5: "GATE", 4: "ENFORCE", 6: "AUDIT" };
    $("#layer-stepper").innerHTML = order.map((layer) => {
      const data = simulation?.layers?.[String(layer)];
      const complete = data?.status === "complete";
      const active = simulation?.current_layer === layer;
      const paused = layer === 5 && simulation?.pending_approval;
      const cls = ["layer-chip", complete ? "complete" : "", active ? "active" : "", paused ? "paused" : ""].filter(Boolean).join(" ");
      return `<button class="${cls}" data-layer="${layer}" aria-label="Inspect layer ${layer}: ${escapeHtml(data?.name || "")}"><span class="layer-number">L${layer}</span><span class="layer-short">${short[layer]}</span></button>`;
    }).join("");
    $$(".layer-chip").forEach((button) => button.addEventListener("click", () => inspectLayer(Number(button.dataset.layer))));
    const completed = simulation?.layers_completed?.length || 0;
    $("#step-count").textContent = `${completed} / 7`;
  }

  function pretty(value) {
    return JSON.stringify(value ?? {}, null, 2);
  }

  function inspectLayer(layer) {
    state.selectedLayer = layer;
    state.selectedDevice = null;
    renderDevices();
    renderStepper();
    const simulation = state.simulation;
    const layerData = simulation?.layers?.[String(layer)];
    const payloadKey = `layer_${layer}_${({ 0: "event", 1: "context", 2: "finding", 3: "proposal", 5: "decision", 4: "result", 6: "audit" }[layer])}`;
    const value = simulation?.payloads?.[payloadKey] ?? layerData?.data ?? { status: "waiting", message: "This layer has not run yet." };
    $("#inspector-title").textContent = `Layer ${layer} · ${layerData?.name || state.catalog?.layers.find((item) => item.id === layer)?.name || "Payload"}`;
    $("#inspector-summary").innerHTML = `<span class="summary-icon">⌁</span><span>${escapeHtml(layerData?.summary || "Select this layer to inspect its output.")}</span>`;
    $("#json-viewer").textContent = pretty(value);
  }

  function inspectDevice(deviceId) {
    const device = state.catalog.devices.find((item) => item.id === deviceId);
    if (!device) return;
    state.selectedDevice = deviceId;
    renderDevices();
    const context = state.simulation?.layer1_contexts?.find((item) => item.asset_id === deviceId);
    const nodeInfo = {
      ...device,
      layer_1_context: context || "No incident context for this node yet.",
      current_status: deviceStatus(device, state.simulation).label,
      safety_rule: device.tier === 1 ? "Surgical blocking only. Never isolate this asset; preserve HL7 2575." : device.tier === 2 ? "Narrow, workflow-aware restrictions." : "Coarse isolation can be used in the digital twin.",
    };
    $("#inspector-title").textContent = device.name;
    $("#inspector-summary").innerHTML = `<span class="summary-icon">⌁</span><span>${escapeHtml(device.zone)} · ${escapeHtml(device.ip)} · Tier ${device.tier}</span>`;
    $("#json-viewer").textContent = pretty(nodeInfo);
    if (state.simulation?.attack_path?.some(([from, to]) => from === deviceId || to === deviceId)) showChainDetails();
  }

  function renderPipelineCurrent() {
    const simulation = state.simulation;
    const container = $("#pipeline-current");
    if (!simulation?.active) {
      container.className = "pipeline-current";
      container.innerHTML = `<span class="current-marker"></span><div><strong>Awaiting simulation</strong><small>Launch a scenario to begin ingestion.</small></div><span class="current-state">READY</span>`;
      return;
    }
    const layer = simulation.current_layer;
    const info = simulation.layers?.[String(layer)] || {};
    const paused = simulation.pending_approval;
    const done = simulation.status === "complete";
    container.className = `pipeline-current${paused ? " paused" : done ? " done" : ""}`;
    const label = paused ? "HUMAN REVIEW" : done ? "COMPLETE" : `LAYER ${layer}`;
    container.innerHTML = `<span class="current-marker"></span><div><strong>${escapeHtml(info.name || "Pipeline ready")}</strong><small>${escapeHtml(paused ? "Layer 4 enforcement is blocked pending reviewer action." : info.summary || simulation.status_message)}</small></div><span class="current-state">${label}</span>`;
  }

  function renderChain() {
    const simulation = state.simulation;
    const hasPath = Boolean(simulation?.active && simulation.attack_path?.length);
    $("#chain-empty").classList.toggle("hidden", hasPath);
    $("#chain-content").classList.toggle("hidden", !hasPath);
    $("#trace-tag").textContent = hasPath ? "ACTIVE TRACE" : "STANDBY";
    $("#trace-tag").classList.toggle("active", hasPath);
    if (!hasPath) return;
    const path = simulation.attack_path;
    const nodes = [path[0][0], ...path.map((pair) => pair[1])];
    $("#chain-flow").innerHTML = nodes.map((nodeId, index) => {
      const isTarget = index === nodes.length - 1;
      const verb = index === 0 ? "COMPROMISED" : isTarget ? "TARGET" : "PIVOT";
      return `${index ? `<span class="chain-arrow">→</span>` : ""}<span class="chain-step ${isTarget ? "target" : ""}"><b>${index + 1}</b><span>${escapeHtml(nodeId)} <small>${verb}</small></span></span>`;
    }).join("");
    $("#chain-source").textContent = `${simulation.source_ip} · ${simulation.source}`;
    const eventIds = simulation.related_event_ids || [];
    $("#chain-events").textContent = eventIds.length > 2 ? `${eventIds[0]}, ${eventIds[1]} +${eventIds.length - 2}` : eventIds.join(", ") || "—";
    $("#chain-blast").textContent = (simulation.blast_radius || []).join(", ") || "—";
    $("#chain-note").textContent = simulation.proposal?.threat_summary || "Select the active red path or a flagged device to inspect this correlated path.";
  }

  function showChainDetails() {
    renderChain();
    $("#chain-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
    const target = state.simulation?.target;
    if (target) {
      const device = state.catalog?.devices.find((item) => item.id === target);
      $("#chain-note").textContent = state.simulation?.proposal?.clinical_impact || `Path terminates at ${device?.name || target}; clinical safety tier ${device?.tier ?? "unknown"}.`;
    }
  }

  function updateHeader() {
    const simulation = state.simulation;
    const status = simulation?.system_status || "NORMAL";
    $("#system-status-text").textContent = status;
    const statusPill = $("#system-status");
    statusPill.className = `status-pill ${status.toLowerCase()}`;
    $("#ledger-status-text").textContent = simulation?.ledger_integrity?.label || "CHAIN VALID";
    $("#ledger-status").classList.toggle("tampered", simulation?.ledger_integrity?.valid === false);
    $("#audit-chain-label").textContent = simulation?.ledger_integrity?.label || "CHAIN VALID";
    const checked = simulation?.ledger_integrity?.records_checked || 0;
    $("#audit-record-count").textContent = `${checked} RECORD${checked === 1 ? "" : "S"}`;
    $("#footer-simulation").textContent = simulation?.simulation_id || "NO ACTIVE RUN";
    $("#baseline-label").textContent = simulation?.active ? `RUN · ${simulation.scenario_label}` : "BEHAVIOR MODEL · LAYER 2";
  }

  function renderAudit() {
    const simulation = state.simulation;
    const buckets = simulation?.narrative_buckets || {};
    $$(".audit-tab").forEach((button) => {
      const entries = buckets[button.dataset.bucket] || [];
      button.querySelector("span").textContent = String(entries.length);
      button.classList.toggle("active", button.dataset.bucket === state.selectedBucket);
    });
    const entries = buckets[state.selectedBucket] || [];
    if (!entries.length) {
      $("#audit-content").innerHTML = `<div class="audit-empty"><span class="audit-empty-mark">◷</span><strong>${simulation?.evidence_ready ? "No records in this bucket" : "Waiting for Layer 6"}</strong><small>${simulation?.evidence_ready ? "Other narrative tabs may contain entries for this incident." : "Verified records and the redacted report will appear when the run completes."}</small></div>`;
    } else {
      $("#audit-content").innerHTML = entries.slice().reverse().map((entry) => `<div class="audit-record"><span class="audit-layer">L${entry.layer}</span><div class="audit-summary">${escapeHtml(entry.summary)}<span class="audit-meta">${escapeHtml(entry.timestamp)} · ${escapeHtml(entry.outcome).toUpperCase()}</span></div></div>`).join("");
    }
    $("#export-evidence").disabled = !simulation?.evidence_ready;
    $("#open-report").disabled = !simulation?.evidence_ready;
    $("#post-rollback").classList.toggle("hidden", !simulation?.rollback_available);
  }

  function fillDecisionModal() {
    const simulation = state.simulation;
    if (!simulation?.pending_approval) {
      $("#decision-modal").classList.add("hidden");
      return;
    }
    const modalWasOpen = !$("#decision-modal").classList.contains("hidden");
    const proposal = simulation.proposal || {};
    const targetId = simulation.decision?.target_asset || proposal.candidate_actions?.find((action) => action.action_type === "SURGICAL_BLOCK")?.target_asset || simulation.target || "icu-monitor-gw";
    const device = state.catalog.devices.find((item) => item.id === targetId) || state.catalog.devices.find((item) => item.tier === 1);
    const action = proposal.candidate_actions?.find((item) => item.target_asset === device.id) || proposal.candidate_actions?.[0];
    const blocked = action?.blocked_flows?.map((flow) => `${flow.protocol} ${flow.port}`).join(", ") || "TCP 445 SMB";
    const preserved = action?.preserved_flows?.map((flow) => `${flow.protocol} port ${flow.port}`).join(", ") || "HL7 port 2575";
    const preservedFlow = action?.preserved_flows?.[0];
    $("#decision-asset").textContent = device.id;
    $("#decision-tier").textContent = `TIER ${device.tier} · ${device.tier === 1 ? "LIFE-CRITICAL" : device.safety}`;
    $("#decision-action").textContent = action?.action_type === "SURGICAL_BLOCK"
      ? `Surgical block: terminate ${blocked} while preserving ${preserved}.`
      : `${action?.action_type || "SCOPED BLOCK"} on ${device.id}; preserve ${preserved}.`;
    $("#decision-modal .action-tag").textContent = (action?.action_type || "SCOPED_BLOCK").replaceAll("_", " ");
    $("#decision-feed-title").textContent = preservedFlow
      ? `${preservedFlow.protocol} PORT ${preservedFlow.port} ACTIVE`
      : "CLINICAL FEED ACTIVE";
    $("#decision-feed-description").textContent = device.tier === 1
      ? "Clinical telemetry remains active throughout containment."
      : `${device.zone} workflow feed remains available.`;
    $("#scope-hash-value").textContent = `sha256:${String(simulation.decision?.scope_hash || proposal.scope_hash || "pending").replace(/^sha256:/, "")}`;
    if (!modalWasOpen) $("#decision-reason").value = "Approved containment after scope review; clinical feeds verified.";
    $("#decision-modal").classList.remove("hidden");
  }

  function renderAll() {
    if (!state.catalog) return;
    renderDevices();
    renderWires();
    renderStepper();
    renderPipelineCurrent();
    renderChain();
    renderAudit();
    updateHeader();
    fillDecisionModal();
    if (state.selectedLayer !== null && !state.selectedDevice) inspectLayer(state.selectedLayer);
  }

  function showModal(id) {
    $("#" + id).classList.remove("hidden");
  }

  function closeModal(id) {
    $("#" + id).classList.add("hidden");
  }

  function renderHelp() {
    const commands = [
      ["PORT SCAN", "attack --type port_scan --src office-ws --dst radiology-ws"],
      ["NEW PEER", "attack --type new_peer --src lab-server --dst icu-monitor-gw"],
      ["EXFILTRATION", "attack --type exfiltration --src office-ws --bytes 750000"],
      ["CREDENTIAL MISUSE", "attack --type credential_misuse --src office-ws"],
      ["OFF-HOURS ACCESS", "attack --type off_hours --src office-ws"],
      ["DIAGNOSTIC DRIFT", "attack --type diagnostic_drift --src radiology-ws"],
      ["BENIGN CLINICAL BURST", "attack --type benign_clinical_burst --src icu-monitor-gw"],
      ["LOW CONFIDENCE", "attack --type low_confidence --src office-ws --dst lab-server"],
    ];
    $("#help-command-grid").innerHTML = commands.map(([label, command]) => `<div class="help-command"><small>${label}</small><code title="${escapeHtml(command)}">${escapeHtml(command)}</code><button data-copy="${escapeHtml(command)}">COPY</button><button data-run="${escapeHtml(command)}">RUN</button></div>`).join("");
    $$("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
      await navigator.clipboard?.writeText(button.dataset.copy);
      showToast("Command copied to clipboard.");
    }));
    $$("[data-run]").forEach((button) => button.addEventListener("click", () => executeTerminalCommand(button.dataset.run)));
  }

  function parseFlags(command) {
    const flags = {};
    const matcher = /--([\w-]+)\s+("[^"]*"|'[^']*'|[^\s]+)/g;
    let match;
    while ((match = matcher.exec(command))) flags[match[1]] = match[2].replace(/^['"]|['"]$/g, "");
    return flags;
  }

  async function launch(payload, sourceLabel = "GUI") {
    addTerminalLine(`${sourceLabel}> ATTACK INJECTION · ${payload.scenario || payload.vector}`, "info");
    const result = await request("/api/attacks", { method: "POST", body: payload });
    state.simulation = result;
    state.selectedLayer = 0;
    state.selectedDevice = null;
    renderAll();
    addTerminalLine(`${result.event_ids.length} event(s) accepted by Layer 0 · run ${result.simulation_id}`, "good");
    showToast("Attack events ingested into the digital twin.");
    return result;
  }

  async function executeTerminalCommand(command) {
    const text = String(command || "").trim();
    if (!text) return;
    addTerminalLine(text, "command");
    const lower = text.toLowerCase();
    if (lower === "clear") {
      $("#terminal-output").innerHTML = "";
      return;
    }
    if (lower === "help") {
      addTerminalLine("Syntax: attack --type <scenario|vector> --src <device> --dst <device> [--bytes n] [--chain node,node,...]", "info");
      addTerminalLine("Commands: help · clear · attack. All activity stays in the local digital twin.", "info");
      $("#help-box").classList.remove("hidden");
      $("#toggle-help").setAttribute("aria-expanded", "true");
      return;
    }
    if (!lower.startsWith("attack ")) {
      addTerminalLine("Unknown command. Type help to view available syntax.", "error");
      return;
    }
    const flags = parseFlags(text);
    const attackType = String(flags.type || "port_scan").toLowerCase();
    const scenarioSet = new Set(state.catalog.scenarios);
    const payload = {
      scenario: scenarioSet.has(attackType) ? attackType : "custom_attack",
      vector: scenarioSet.has(attackType) ? undefined : attackType.toUpperCase(),
      source: flags.src || undefined,
      target: flags.dst || undefined,
      bytes: flags.bytes ? Number(flags.bytes) : undefined,
      chain: flags.chain ? flags.chain.split(",").map((node) => node.trim()).filter(Boolean) : undefined,
    };
    try {
      await launch(payload, "CLI");
    } catch (error) {
      addTerminalLine(error.message, "error");
      showToast(error.message, "error");
    }
  }

  async function runPipeline(stepOnly = false) {
    const button = stepOnly ? $("#step-layer") : $("#run-pipeline");
    if (!state.simulation?.active) {
      showToast("Launch an attack before advancing the pipeline.", "error");
      return;
    }
    button.disabled = true;
    try {
      const result = await request(stepOnly ? "/api/step" : "/api/run", { method: "POST", body: {} });
      state.simulation = result;
      renderAll();
      if (result.pending_approval) {
        addTerminalLine(`Layer 5 paused · reviewer action required for ${result.decision?.target_asset}.`, "error");
      } else if (result.status === "complete") {
        addTerminalLine(`Pipeline complete · ${result.ledger_integrity?.records_checked || 0} audit records verified.`, "good");
      } else if (stepOnly) {
        addTerminalLine(`Advanced to Layer ${result.current_layer} · ${result.layers[String(result.current_layer)]?.summary || ""}`, "info");
      }
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  async function applyDecision(decision) {
    const reviewer = $("#reviewer-id").value.trim();
    const reason = $("#decision-reason").value.trim();
    if (!reviewer) {
      showToast("Enter a reviewer ID before recording this decision.", "error");
      return;
    }
    try {
      const result = await request("/api/decisions", { method: "POST", body: { decision, reviewer, reason } });
      state.simulation = result;
      closeModal("decision-modal");
      renderAll();
      addTerminalLine(`Layer 5 ${decision.toLowerCase()} · ${reviewer} · scope ${result.decision?.scope_hash || "recorded"}`, decision === "APPROVED" ? "good" : "info");
      showToast(`Decision recorded. ${decision === "APPROVED" ? "Continuing to simulated enforcement." : "Enforcement skipped."}`);
    } catch (error) {
      showToast(error.message, "error");
    }
  }

  async function triggerRollback() {
    const reviewer = $("#reviewer-id").value.trim() || "SOC operator";
    try {
      const result = await request("/api/rollback", { method: "POST", body: { reviewer } });
      state.simulation = result;
      closeModal("decision-modal");
      renderAll();
      addTerminalLine("Proposal canceled before enforcement; no containment was applied.", "info");
      showToast("Pending action canceled and audit record updated.");
    } catch (error) {
      showToast(error.message, "error");
    }
  }

  function populateScenarioDefaults(scenario) {
    const preset = state.catalog.presets[scenario];
    if (!preset) return;
    $("#attack-source").value = preset.source;
    $("#attack-target").value = preset.target;
    $("#attack-vector").value = preset.vector === "EXFILTRATION" || preset.vector === "OFF_HOURS_ACCESS" || preset.vector === "NEW_PEER" || preset.vector === "CLINICAL_BURST"
      ? ({ EXFILTRATION: "MALWARE_STAGING", OFF_HOURS_ACCESS: "CREDENTIAL_DUMP", NEW_PEER: "LATERAL_MOVEMENT", CLINICAL_BURST: "LATERAL_MOVEMENT" }[preset.vector])
      : preset.vector;
    const isChain = scenario === "new_peer";
    $("#chain-toggle").checked = isChain;
    $("#chain-picker").classList.toggle("hidden", !isChain);
    state.chainPath = isChain ? [preset.source, preset.target] : [];
    $("#chain-next-hop").value = preset.target;
    renderChainSequence();
  }

  function openAttackDialog() {
    $("#scenario-select").value = "custom_attack";
    $("#attack-source").value = "office-ws";
    $("#attack-target").value = "radiology-ws";
    $("#attack-vector").value = "PORT_SCAN";
    $("#chain-toggle").checked = false;
    $("#chain-picker").classList.add("hidden");
    state.chainPath = [];
    $("#chain-next-hop").value = "radiology-ws";
    renderChainSequence();
    showModal("attack-modal");
  }

  async function submitAttackForm(event) {
    event.preventDefault();
    const scenario = $("#scenario-select").value;
    const chainEnabled = $("#chain-toggle").checked;
    const selectedChain = state.chainPath;
    const payload = {
      scenario,
      source: $("#attack-source").value,
      target: $("#attack-target").value,
      vector: scenario === "custom_attack" ? $("#attack-vector").value : undefined,
      chain: chainEnabled ? selectedChain : undefined,
    };
    try {
      await launch(payload, "GUI");
      closeModal("attack-modal");
    } catch (error) {
      showToast(error.message, "error");
    }
  }

  function showReport() {
    const report = state.simulation?.redacted_timeline_md;
    if (!report) return;
    const overlay = document.createElement("div");
    overlay.className = "modal-backdrop report-overlay";
    overlay.innerHTML = `<section class="modal report-dialog"><div class="modal-topline"><span>LAYER 6 / REDACTED MARKDOWN REPORT</span><button class="modal-close" aria-label="Close report">×</button></div><pre class="report-viewer"></pre><div class="modal-actions"><button class="button button-quiet report-close">Close</button><button class="button button-primary report-download">Download .md</button></div></section>`;
    $(".report-viewer", overlay).textContent = report;
    document.body.append(overlay);
    $(".modal-close", overlay).addEventListener("click", () => overlay.remove());
    $(".report-close", overlay).addEventListener("click", () => overlay.remove());
    $(".report-download", overlay).addEventListener("click", () => downloadText(`ACCDS-${state.simulation.simulation_id}-report.md`, report, "text/markdown"));
    overlay.addEventListener("click", (event) => { if (event.target === overlay) overlay.remove(); });
  }

  function downloadText(name, text, type) {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([text], { type }));
    link.download = name;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  function bindEvents() {
    $("#open-attack").addEventListener("click", openAttackDialog);
    $("#open-terminal").addEventListener("click", () => {
      const panel = $("#terminal-panel");
      const open = panel.classList.toggle("collapsed") === false;
      $("#open-terminal").setAttribute("aria-expanded", String(open));
      $("#terminal-toggle-label").textContent = open ? "Close attack terminal" : "Open attack terminal";
      if (open) {
        panel.scrollIntoView({ behavior: "smooth", block: "center" });
        $("#terminal-input").focus({ preventScroll: true });
      }
    });
    $("#run-pipeline").addEventListener("click", () => runPipeline(false));
    $("#step-layer").addEventListener("click", () => runPipeline(true));
    $("#reset-sim").addEventListener("click", async () => {
      try {
        state.simulation = await request("/api/reset", { method: "POST", body: {} });
        state.selectedLayer = 0;
        state.selectedDevice = null;
        renderAll();
        addTerminalLine("Simulation state reset. Existing evidence artifacts are preserved.", "info");
        showToast("Digital-twin state reset.");
      } catch (error) { showToast(error.message, "error"); }
    });
    $("#attack-form").addEventListener("submit", submitAttackForm);
    $("#scenario-select").addEventListener("change", (event) => populateScenarioDefaults(event.target.value));
    $("#chain-toggle").addEventListener("change", (event) => $("#chain-picker").classList.toggle("hidden", !event.target.checked));
    $("#chain-toggle").addEventListener("change", (event) => {
      if (event.target.checked && state.chainPath.length < 2) {
        state.chainPath = [$("#attack-source").value];
        $("#chain-next-hop").value = $("#attack-target").value;
        renderChainSequence();
      }
    });
    $("#attack-source").addEventListener("change", () => {
      if ($("#chain-toggle").checked) {
        state.chainPath = [$("#attack-source").value];
        renderChainSequence();
      }
    });
    $("#attack-target").addEventListener("change", () => {
      if (state.chainPath.length < 2) $("#chain-next-hop").value = $("#attack-target").value;
    });
    $("#append-hop").addEventListener("click", () => {
      const next = $("#chain-next-hop").value;
      const current = state.chainPath.at(-1) || $("#attack-source").value;
      if (next === current) {
        showToast("Choose a different device for the next hop.", "error");
        return;
      }
      if (!state.chainPath.length) state.chainPath = [$("#attack-source").value];
      state.chainPath.push(next);
      $("#attack-target").value = next;
      renderChainSequence();
    });
    $("#clear-chain").addEventListener("click", () => {
      state.chainPath = [$("#attack-source").value];
      renderChainSequence();
    });
    $("#terminal-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const input = $("#terminal-input");
      const command = input.value;
      input.value = "";
      executeTerminalCommand(command);
    });
    $("#clear-terminal").addEventListener("click", () => { $("#terminal-output").innerHTML = ""; });
    $("#toggle-help").addEventListener("click", () => {
      const box = $("#help-box");
      const open = box.classList.toggle("hidden") === false;
      $("#toggle-help").setAttribute("aria-expanded", String(open));
    });
    $("#close-help").addEventListener("click", () => {
      $("#help-box").classList.add("hidden");
      $("#toggle-help").setAttribute("aria-expanded", "false");
    });
    $$("[data-close]").forEach((button) => button.addEventListener("click", () => closeModal(button.dataset.close)));
    $("#approve-action").addEventListener("click", () => applyDecision("APPROVED"));
    $("#reject-action").addEventListener("click", () => applyDecision("REJECTED"));
    $("#rollback-action").addEventListener("click", triggerRollback);
    $("#post-rollback").addEventListener("click", async () => {
      try {
        state.simulation = await request("/api/rollback", { method: "POST", body: { reviewer: $("#reviewer-id").value.trim() || "SOC operator" } });
        renderAll();
        addTerminalLine("Active digital-twin rules restored and rollback appended to the audit chain.", "good");
        showToast("Digital-twin action rolled back.");
      } catch (error) { showToast(error.message, "error"); }
    });
    $("#copy-hash").addEventListener("click", async () => {
      await navigator.clipboard?.writeText($("#scope-hash-value").textContent);
      showToast("Scope hash copied.");
    });
    $("#audit-tabs").addEventListener("click", (event) => {
      const button = event.target.closest(".audit-tab");
      if (!button) return;
      state.selectedBucket = button.dataset.bucket;
      renderAudit();
    });
    $("#export-evidence").addEventListener("click", () => {
      if (state.simulation?.evidence_ready) window.location.href = "/api/evidence.zip";
    });
    $("#open-report").addEventListener("click", showReport);
    document.addEventListener("click", (event) => {
      if (event.target.classList.contains("modal-backdrop")) event.target.classList.add("hidden");
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") $$(".modal-backdrop").forEach((modal) => modal.classList.add("hidden"));
      if (event.key === "Enter" && document.activeElement !== $("#terminal-input") && !$("#attack-modal").classList.contains("hidden")) return;
    });
  }

  function connectStream() {
    const source = new EventSource("/api/stream");
    state.eventSource = source;
    source.addEventListener("snapshot", (event) => {
      try {
        const incoming = JSON.parse(event.data);
        state.simulation = incoming;
        if (!incoming.pending_approval && !$("#decision-modal").classList.contains("hidden")) closeModal("decision-modal");
        renderAll();
      } catch (error) {
        console.warn("Could not read simulator stream event", error);
      }
    });
    source.onerror = () => {
      $("#system-status-text").textContent = "RECONNECTING";
      $("#system-status").className = "status-pill heightened_monitoring";
    };
  }

  async function init() {
    bindEvents();
    nowClock();
    setInterval(nowClock, 1000);
    try {
      [state.catalog, state.simulation] = await Promise.all([request("/api/catalog"), request("/api/state")]);
      populateInputs();
      renderAll();
      connectStream();
    } catch (error) {
      showToast("Could not connect to the local simulator API. Start it with python -m src.simulator.server.", "error");
      console.error(error);
    }
  }

  init();
})();
