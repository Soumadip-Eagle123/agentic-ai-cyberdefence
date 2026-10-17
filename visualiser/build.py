"""Builds the ACCDS topology view from a pipeline run.

Reads ``topology.json`` (written by ``main.py``) and emits one self-contained
HTML file. No server, no build step, no dependencies - open the file.

The layout groups devices into zone rooms, because "the attack crossed from
administration into intensive care" is the fact a viewer should grasp instantly.
The *lines*, though, are network reachability rather than walls: ``ehr-core``
sits in one room and legitimately talks to the whole hospital, while
``guest-device`` could be metres from the ICU and must never reach it. Drawing
physical adjacency would show the wrong graph entirely.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

CANVAS_W, CANVAS_H = 1000, 620

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACCDS Hospital</title>
<style>
  :root {
    --bg: #0b1020; --panel: #141a2e; --line: #243049; --text: #e8edf7;
    --muted: #8b97b4; --t1: #ef4444; --t2: #f59e0b; --t3: #38bdf8;
    --safe: #22c55e; --attack: #ff3b5c;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  header { padding: 18px 24px 8px; }
  h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); font-size: 13px; max-width: 70ch; }
  .wrap { display: flex; gap: 16px; padding: 12px 24px 24px; align-items: flex-start; flex-wrap: wrap; }
  .stage-wrap { flex: 1 1 640px; min-width: 0; }
  svg { width: 100%; height: auto; display: block; background: #0d1326; border: 1px solid var(--line); border-radius: 14px; }
  .room { fill: #121a30; stroke: var(--line); stroke-width: 1.5; }
  .room-label { fill: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; }
  .edge-base { stroke: #2b3755; stroke-width: 1.5; fill: none; }
  .edge-atk { stroke: var(--attack); stroke-width: 3; fill: none; filter: drop-shadow(0 0 6px rgba(255,59,92,.6)); }
  .node { cursor: pointer; }
  .node circle.body { fill: #1b2742; stroke-width: 3; transition: fill .2s, r .2s; }
  .node.hit circle.body { fill: #3a1420; }
  .node.sel circle.body { fill: #26354f; }
  .node text { fill: var(--text); font-size: 10.5px; text-anchor: middle; pointer-events: none; }
  .node .ip { fill: var(--muted); font-size: 9px; }
  .pulse { fill: none; stroke: var(--attack); stroke-width: 2; opacity: 0; }
  .panel { flex: 0 1 330px; min-width: 280px; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
  .panel h2 { margin: 0 0 10px; font-size: 14px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); }
  .kv { display: grid; grid-template-columns: 96px 1fr; gap: 4px 10px; font-size: 12.5px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; word-break: break-word; }
  .tier { display: inline-block; padding: 1px 7px; border-radius: 99px; font-size: 11px; font-weight: 700; }
  .tier1 { background: rgba(239,68,68,.18); color: var(--t1); }
  .tier2 { background: rgba(245,158,11,.18); color: var(--t2); }
  .tier3 { background: rgba(56,189,248,.18); color: var(--t3); }
  .controls { display: flex; gap: 8px; align-items: center; margin: 12px 0 8px; flex-wrap: wrap; }
  button { background: #1d2740; color: var(--text); border: 1px solid var(--line); border-radius: 8px;
           padding: 7px 14px; font-size: 13px; cursor: pointer; font-weight: 600; }
  button:hover { background: #26324f; }
  button.primary { background: var(--attack); border-color: var(--attack); color: #fff; }
  input[type=range] { flex: 1 1 180px; accent-color: var(--attack); }
  .stage-line { font-size: 12.5px; padding: 7px 9px; border-left: 3px solid var(--line);
                margin-bottom: 5px; background: #0f1628; border-radius: 0 7px 7px 0; opacity: .35; }
  .stage-line.on { opacity: 1; border-left-color: var(--attack); }
  .stage-line.t1.on { background: rgba(239,68,68,.12); }
  .stage-line b { color: #fff; }
  .legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11.5px; color: var(--muted); margin-top: 10px; }
  .legend i { display: inline-block; width: 18px; height: 3px; vertical-align: middle; margin-right: 5px; border-radius: 2px; }
  .banner { padding: 10px 12px; border-radius: 9px; font-size: 12.5px; margin-bottom: 12px; font-weight: 600; }
  .banner.crit { background: rgba(239,68,68,.14); border: 1px solid rgba(239,68,68,.4); color: #ffb3bf; }
  .banner.ok { background: rgba(34,197,94,.12); border: 1px solid rgba(34,197,94,.35); color: #a7f3c4; }
  .muted { color: var(--muted); }
  .chip { display: inline-block; background: #1d2740; border-radius: 6px; padding: 1px 7px; margin: 2px 3px 0 0; font-size: 11px; }
  @media (max-width: 880px) { .wrap { padding: 12px 16px 24px; } }
</style>
</head>
<body>
<header>
  <h1>__TITLE__</h1>
  <div class="sub">__DESC__</div>
</header>

<div class="wrap">
  <div class="stage-wrap">
    <svg id="stage" viewBox="0 0 __W__ __H__" role="img" aria-label="Hospital network topology"></svg>
    <div class="controls">
      <button id="play" class="primary">Play attack</button>
      <button id="step">Step</button>
      <button id="reset">Reset</button>
      <input type="range" id="scrub" min="0" max="__NSTAGES__" value="0">
      <span id="clock" class="muted"></span>
    </div>
    <div class="legend">
      <span><i style="background:#2b3755"></i>permitted link (baseline)</span>
      <span><i style="background:#ff3b5c"></i>attack traffic</span>
      <span><i style="background:#ef4444"></i>Tier 1 life-critical</span>
      <span><i style="background:#f59e0b"></i>Tier 2 clinical</span>
      <span><i style="background:#38bdf8"></i>Tier 3 non-clinical</span>
    </div>
  </div>

  <div class="panel">
    <div id="verdict"></div>
    <h2>Attack path</h2>
    <div id="stages"></div>
    <h2 style="margin-top:18px">Device</h2>
    <div id="detail" class="muted">Click any device for its asset context.</div>
  </div>
</div>

<script>
const DATA = __DATA__;
const W = __W__, H = __H__;
const svg = document.getElementById('stage');
const NS = 'http://www.w3.org/2000/svg';

function el(tag, attrs = {}, parent = svg) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  parent.appendChild(node);
  return node;
}

// --- geometry: device position = its zone's room + its fractional offset ---
const zoneByName = Object.fromEntries(DATA.zones.map(z => [z.name, z]));
const pos = {};
for (const d of DATA.devices) {
  const z = zoneByName[d.zone];
  if (!z) continue;
  const [x, y, w, h] = z.rect;
  pos[d.asset_id] = { x: x + d.pos[0] * w, y: y + d.pos[1] * h, d };
}

// --- rooms ---
for (const z of DATA.zones) {
  const [x, y, w, h] = z.rect;
  el('rect', { x, y, width: w, height: h, rx: 14, class: 'room' });
  el('rect', { x: x, y: y, width: 4, height: h, rx: 2, fill: z.accent, opacity: .55 });
  const label = el('text', { x: x + 14, y: y + 21, class: 'room-label' });
  label.textContent = z.label;
}

// --- baseline reachability edges (NOT walls) ---
const edgeLayer = el('g');
for (const [a, b] of DATA.baseline_edges) {
  if (!pos[a] || !pos[b]) continue;
  el('line', { x1: pos[a].x, y1: pos[a].y, x2: pos[b].x, y2: pos[b].y, class: 'edge-base' }, edgeLayer);
}

// --- attack edge layer, drawn above baseline ---
const atkLayer = el('g');

// --- device nodes ---
const TIER_COLOR = { 1: '#ef4444', 2: '#f59e0b', 3: '#38bdf8' };
const nodeEls = {};
for (const d of DATA.devices) {
  const p = pos[d.asset_id];
  if (!p) continue;
  const g = el('g', { class: 'node', tabindex: '0' });
  const ring = d.tier === 1 ? 4.5 : d.tier === 2 ? 3 : 2;
  el('circle', { class: 'pulse', cx: p.x, cy: p.y, r: 16 }, g);
  el('circle', {
    class: 'body', cx: p.x, cy: p.y, r: d.tier === 1 ? 17 : 14,
    stroke: TIER_COLOR[d.tier], 'stroke-width': ring
  }, g);
  const name = el('text', { x: p.x, y: p.y + 33 }, g);
  name.textContent = d.asset_id;
  const ip = el('text', { x: p.x, y: p.y + 45, class: 'ip' }, g);
  ip.textContent = d.ip;
  g.addEventListener('click', () => selectDevice(d.asset_id));
  g.addEventListener('keypress', e => { if (e.key === 'Enter') selectDevice(d.asset_id); });
  nodeEls[d.asset_id] = g;
}

// --- side panel: stage list ---
const stagesBox = document.getElementById('stages');
DATA.stages.forEach((s, i) => {
  const div = document.createElement('div');
  div.className = 'stage-line' + (s.tier === 1 ? ' t1' : '');
  div.id = 'stage-' + i;
  const tierTag = `<span class="tier tier${s.tier}">T${s.tier}</span>`;
  const score = s.finding ? ` &middot; risk ${s.finding.risk_score}` : ' &middot; <span class="muted">below threshold</span>';
  div.innerHTML = `<b>${i + 1}. ${s.src}</b> &rarr; <b>${s.dst}</b> ${tierTag}<br>
    <span class="muted">${s.event_type}${score}</span>`;
  div.addEventListener('click', () => goTo(i + 1));
  stagesBox.appendChild(div);
});

// --- verdict banner ---
const dec = DATA.decision, enf = DATA.enforcement;
const vbox = document.getElementById('verdict');
if (dec) {
  const approved = String(dec.decision).toUpperCase() === 'APPROVED';
  vbox.innerHTML = `<div class="banner ${approved ? 'ok' : 'crit'}">
    Layer 5: ${dec.decision} by ${dec.reviewer}<br>
    <span style="font-weight:400">${dec.reason || ''}</span><br>
    <span style="font-weight:400" class="muted">Layer 4: ${enf ? enf.status : 'n/a'}</span>
  </div>`;
}

// --- device detail ---
function selectDevice(id) {
  Object.values(nodeEls).forEach(n => n.classList.remove('sel'));
  nodeEls[id] && nodeEls[id].classList.add('sel');
  const d = DATA.devices.find(x => x.asset_id === id);
  if (!d) return;
  const hits = DATA.stages.filter(s => s.dst === id || s.asset_id === id);
  document.getElementById('detail').innerHTML = `
    <dl class="kv">
      <dt>Asset</dt><dd>${d.asset_id}</dd>
      <dt>Type</dt><dd>${d.asset_type}</dd>
      <dt>Zone</dt><dd>${d.zone}</dd>
      <dt>Tier</dt><dd><span class="tier tier${d.tier}">Tier ${d.tier}</span></dd>
      <dt>IP</dt><dd>${d.ip}</dd>
      <dt>Vendor</dt><dd>${d.vendor} ${d.software_version}</dd>
      <dt>Fallback</dt><dd>${d.fallback_mode}</dd>
      <dt>Services</dt><dd>${d.services.map(s => `<span class="chip">${s}</span>`).join('')}</dd>
      <dt>Can reach</dt><dd>${d.peers.map(s => `<span class="chip">${s}</span>`).join('')}</dd>
      <dt>Constraints</dt><dd>${d.constraints.join('; ')}</dd>
      <dt>Hit by</dt><dd>${hits.length ? hits.map(h => 'stage ' + h.stage).join(', ') : '<span class="muted">not targeted</span>'}</dd>
    </dl>`;
}

// --- playback ---
let cursor = 0, timer = null;
const scrub = document.getElementById('scrub');
const clock = document.getElementById('clock');

function render() {
  atkLayer.innerHTML = '';
  Object.values(nodeEls).forEach(n => n.classList.remove('hit'));
  DATA.stages.forEach((s, i) => {
    const on = i < cursor;
    document.getElementById('stage-' + i).classList.toggle('on', on);
    if (!on) return;
    const a = pos[s.src], b = pos[s.dst] || pos[s.asset_id];
    if (a && b) {
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - 38;
      el('path', { d: `M${a.x},${a.y} Q${mx},${my} ${b.x},${b.y}`, class: 'edge-atk' }, atkLayer);
      const n = Math.round((i + 1));
      const badge = el('circle', { cx: mx, cy: my + 19, r: 9, fill: '#ff3b5c' }, atkLayer);
      const t = el('text', { x: mx, y: my + 22.5, 'text-anchor': 'middle',
                             'font-size': '10', 'font-weight': '700', fill: '#fff' }, atkLayer);
      t.textContent = n;
    }
    const victim = s.dst in nodeEls ? s.dst : s.asset_id;
    nodeEls[victim] && nodeEls[victim].classList.add('hit');
  });
  scrub.value = cursor;
  const last = DATA.stages[cursor - 1];
  clock.textContent = cursor === 0
    ? 'before the attack'
    : `stage ${cursor} of ${DATA.stages.length} · ${(last.timestamp || '').slice(11, 16)}`;
}

function goTo(n) {
  cursor = Math.max(0, Math.min(DATA.stages.length, n));
  render();
}
function stop() { clearInterval(timer); timer = null; document.getElementById('play').textContent = 'Play attack'; }
document.getElementById('step').onclick = () => { stop(); goTo(cursor + 1); };
document.getElementById('reset').onclick = () => { stop(); goTo(0); };
scrub.oninput = e => { stop(); goTo(+e.target.value); };
document.getElementById('play').onclick = function () {
  if (timer) return stop();
  if (cursor >= DATA.stages.length) goTo(0);
  this.textContent = 'Pause';
  timer = setInterval(() => {
    if (cursor >= DATA.stages.length) return stop();
    goTo(cursor + 1);
  }, 1100);
};

render();
</script>
</body>
</html>
"""


def build(data: Dict[str, Any]) -> str:
    campaign = data.get("campaign", {})
    return (
        HTML.replace("__TITLE__", campaign.get("title", "ACCDS Hospital"))
        .replace("__DESC__", campaign.get("description", ""))
        .replace("__NSTAGES__", str(len(data.get("stages", []))))
        .replace("__W__", str(CANVAS_W))
        .replace("__H__", str(CANVAS_H))
        .replace("__DATA__", json.dumps(data))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the ACCDS topology view")
    parser.add_argument("--data", type=Path, default=Path("artifacts/full_run/topology.json"))
    parser.add_argument("--out", type=Path, default=Path("artifacts/full_run/topology.html"))
    args = parser.parse_args()

    if not args.data.is_file():
        print(f"error: {args.data} not found. Run `python main.py` first.")
        return 2

    data = json.loads(args.data.read_text(encoding="utf-8"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(data), encoding="utf-8")

    stages = len(data.get("stages", []))
    devices = len(data.get("devices", []))
    print(f"Built {args.out}")
    print(f"  {devices} devices, {len(data.get('zones', []))} zones, {stages} attack stages")
    print(f"\nOpen it:  xdg-open {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
