/* NetWatch extra views: request checker (packet capture), network map, public-IP history, hash changes.
   Loaded after the main script; reuses its globals ($, esc, post, fmtN, showTip, hideTip, sevBadge, repBadge, openProc). */
(function () {
  const css = `
  .ibtn{background:none;border:1px solid var(--line);border-radius:5px;color:var(--mut);cursor:pointer;padding:0 6px;font-size:12px;line-height:18px}
  .ibtn:hover{color:var(--acc);border-color:var(--acc)}
  .cap-modal .mbox{width:min(1200px,100%);max-height:94vh;display:flex;flex-direction:column}
  .cap-modal .bd{overflow:auto}
  .cap-grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:12px}
  .cap-pk{max-height:46vh;overflow:auto;border:1px solid var(--line);border-radius:8px}
  .cap-pk tr.sel td{background:#1d3048}
  .hex{font-family:var(--mono);font-size:11.5px;white-space:pre;overflow:auto;max-height:30vh;background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:8px}
  .kvs{display:grid;grid-template-columns:120px 1fr;gap:3px 10px;font-size:12px}
  .kvs div:nth-child(odd){color:var(--mut)} .kvs div{word-break:break-all}
  .chipline{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}
  .bar{height:6px;background:#1f2733;border-radius:3px;overflow:hidden} .bar i{display:block;height:100%;background:var(--acc)}
  .dir-out{color:var(--acc)} .dir-in{color:#7ee0c3}
  #nmWrap{position:relative;display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:12px;height:calc(100vh - 210px);min-height:420px}
  #nmSvg{width:100%;height:100%;background:var(--panel);border:1px solid var(--line);border-radius:10px;cursor:grab;user-select:none}
  #nmSvg.drag{cursor:grabbing}
  #nmSide{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;overflow:auto}
  .nm-node text{font-size:11.5px;fill:var(--text);pointer-events:none} .nm-node .sub{fill:var(--mut);font-size:10.5px}
  .nm-node circle{stroke:#0b0f14;stroke-width:2;cursor:pointer} .nm-node.sel circle{stroke:var(--acc);stroke-width:3}
  .nm-node.stale{opacity:.5} .nm-node .newring{fill:none;stroke:var(--good);stroke-width:2;stroke-dasharray:3 3}
  .nm-edge{stroke:#3a4554;stroke-width:1.5}
  .lane-lab{font-size:11px;fill:var(--mut)} .tl-axis{font-size:10.5px;fill:#8b98a9}
  .verchain{display:flex;flex-wrap:wrap;align-items:center;gap:4px;font-size:11.5px}
  .ver{border:1px solid var(--line);border-radius:6px;padding:2px 7px;background:var(--panel2);font-family:var(--mono)}
  .ver.bad{border-color:#6b2222;color:#ff8a8a}`;
  document.head.insertAdjacentHTML('beforeend', `<style>${css}</style>`);

  /* ---------- tabs + views ---------- */
  const nav = document.querySelector('nav'), main = document.querySelector('main');
  const before = nav.querySelector('[data-v="web"]');
  [['netmap', 'Network map'], ['iphist', 'IP history'], ['hashes', 'Hash changes']].forEach(([v, label]) => {
    const b = document.createElement('button'); b.dataset.v = v; b.textContent = label;
    b.onclick = () => goView(v); nav.insertBefore(b, before);
  });
  main.insertAdjacentHTML('beforeend', `
  <section class="view" id="v-netmap">
    <div class="dhead" style="flex-wrap:wrap"><h3>Network map</h3>
      <button class="btn pri" id="nmSweep">Scan network</button>
      <button class="btn" id="nmListen" title="Passively record broadcast/multicast (ARP, mDNS, SSDP, NetBIOS, LLMNR, DHCP) to learn device names">Listen 45 s</button>
      <button class="btn" id="nmTrace">Trace ISP path</button>
      <button class="btn" id="nmOui" style="display:none">Download vendor list (IEEE, ~6 MB)</button>
      <span class="mut" id="nmState" style="font-size:12px"></span><span class="spacer"></span>
      <button class="btn" id="nmFit">Fit</button></div>
    <div class="mut" style="font-size:11.5px;margin:-6px 0 8px">Drag the background to pan, scroll to zoom, drag nodes to rearrange, click a node for details. Wi-Fi can't use promiscuous mode on Windows, so devices are found by ARP and by the broadcasts every device sends.</div>
    <div id="nmWrap"><svg id="nmSvg"></svg><div id="nmSide"><div class="mut">Click a node.</div></div></div>
  </section>
  <section class="view" id="v-iphist">
    <div class="dhead" style="flex-wrap:wrap"><h3>Public IP history</h3>
      <div class="seg" id="ipRange"><button data-h="24">24h</button><button data-h="168" class="on">7d</button><button data-h="720">30d</button></div>
      <button class="btn" id="ipCheck">Check now</button><span class="mut" id="ipState" style="font-size:12px"></span></div>
    <div class="kpis" id="ipKpis"></div>
    <div class="panel"><div class="ph"><b>Which IP was in use when</b><span class="mut">gaps = PC asleep, offline or not running NetWatch</span>
      <span class="legend"><span><span class="sw" style="background:var(--s1)"></span>IPv4</span><span><span class="sw" style="background:var(--s3)"></span>IPv6</span></span></div><div id="ipChart"></div></div>
    <div class="panel"><div class="ph"><b>What was my IP at…?</b><span class="mut">e.g. the time on an AbuseIPDB report</span></div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><input type="datetime-local" id="ipAt" step="60" style="background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:6px 10px;font:inherit">
      <label class="chk"><input type="checkbox" id="ipUtc"> time is UTC</label><button class="btn" id="ipAtBtn">Look up</button><span id="ipAtRes"></span></div></div>
    <table><thead><tr><th>IP</th><th>Family</th><th>From</th><th>To</th><th>Duration</th><th>Interface</th><th>VPN</th><th>AbuseIPDB</th><th>Note</th></tr></thead><tbody id="tIp"></tbody></table>
  </section>
  <section class="view" id="v-hashes">
    <div class="dhead" style="flex-wrap:wrap"><h3>File hash changes</h3><button class="btn" id="hsRescan">Re-check now</button><span class="mut" id="hsState" style="font-size:12px"></span></div>
    <div class="kpis" id="hsKpis"></div>
    <div class="grid2" style="margin-bottom:12px"><div class="panel"><div class="ph"><b>Change map by folder</b></div><div id="hsMap"></div></div>
      <div class="panel"><div class="ph"><b>How changes are rated</b></div><div class="mut" style="font-size:12px;line-height:1.7">
      ${sevBadge('critical')} new version's signature is broken (file modified after signing)<br>${sevBadge('high')} lost its valid signature, signer changed, or a Windows system file became unsigned<br>
      ${sevBadge('medium')} changed and is not validly signed<br>${sevBadge('info')} normal update, same valid signer</div></div></div>
    <table><thead><tr><th>Latest</th><th>File</th><th>Version history (oldest → newest)</th><th>Used by</th><th>Last change</th></tr></thead><tbody id="tHs"></tbody></table>
  </section>`);
  ['hash_change', 'ip_change', 'device_new'].forEach(k => { if (!KINDS.includes(k)) { KINDS.push(k); kindOn.add(k); } });
  document.head.insertAdjacentHTML('beforeend', `<style>.e-hash_change{color:#ec835a}.e-ip_change{color:var(--acc)}.e-device_new{color:#7ee0c3}</style>`);

  window.extraViews = {netmap: loadMap, iphist: loadIp, hashes: loadHashes};

  /* ---------- request checker ---------- */
  document.body.insertAdjacentHTML('beforeend', `<div id="capModal" class="modal cap-modal" onclick="if(event.target===this)capClose()"><div class="mbox">
    <div class="hd"><h2 id="capTitle">Packet capture</h2><button class="x" onclick="capClose()">×</button></div><div class="bd" id="capBody"></div></div></div>`);
  let capPoll = null, capData = null, capTarget = null;
  window.capClose = () => { $('#capModal').classList.remove('on'); clearInterval(capPoll); };
  window.inspectFrom = el => inspectReq({remote: el.dataset.r || '', host: el.dataset.h || '', process: el.dataset.p || ''});
  window.inspectReq = t => {
    capTarget = t; capData = null;
    $('#capTitle').textContent = 'Request checker – packet capture';
    $('#capBody').innerHTML = `
      <div class="repcard"><div class="kvs"><div>Target</div><div class="mono">${esc(t.host || '')} ${t.remote ? esc(t.remote) : ''}</div>
      ${t.process ? `<div>Process</div><div>${esc(t.process)}</div>` : ''}</div>
      <div class="mut small" style="margin-top:8px">Packets can't be captured after the fact. Start the capture, then make the request happen again (reload the page, retry the app). Captures use Windows' built-in <b>pktmon</b> at the network card, so NetWatch needs Administrator. HTTPS content stays encrypted, but you'll see the handshake, the server name (SNI), timing, sizes and any plaintext HTTP or DNS.</div>
      <div style="display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap">
        <label>Duration <select id="capSec"><option>10</option><option selected>20</option><option>30</option><option>60</option><option>120</option></select> s</label>
        <label class="chk"><input type="checkbox" id="capDns" checked> include DNS lookups</label>
        <label class="chk"><input type="checkbox" id="capPort" checked> only this port</label>
        <button class="btn pri" id="capStart">Start capture</button><span id="capMsg" class="mut"></span></div></div>
      <div id="capOut"></div>`;
    $('#capStart').onclick = capStart;
    $('#capModal').classList.add('on');
    showRecent();
  };
  async function showRecent() {
    const s = await fetch('/api/capture/status').then(r => r.json());
    if (s.running && s.kind === 'request') return watch(s.id);
    if (s.running) { $('#capOut').innerHTML = `<div class="repcard mut">Another capture is running (${esc(s.label)}, ${Math.round(s.elapsed)}/${s.seconds} s). pktmon runs one capture at a time; start yours when it finishes.</div>`; return; }
    if (s.recent && s.recent.length && !capData) $('#capOut').innerHTML = `<div class="mut small" style="margin-top:6px">Recent captures: ${s.recent.map(r => `<a href="#" class="vt" onclick="capLoad('${esc(r.id)}');return false">${esc(r.label)} (${r.error ? 'error' : r.packets + ' pkts'})</a>`).join(' · ')}</div>`;
  }
  async function capStart() {
    const r = await post('/api/capture/start', {remote: capTarget.remote, host: capTarget.host, seconds: +$('#capSec').value, dns: $('#capDns').checked, port_only: $('#capPort').checked});
    if (r.error) { $('#capMsg').innerHTML = `<span class="fail">${esc(r.error)}</span>`; return; }
    watch(r.id);
  }
  function watch(id) {
    clearInterval(capPoll);
    const tick = async () => {
      const s = await fetch('/api/capture/status').then(r => r.json()).catch(() => ({}));
      if (s.running && s.id === id) {
        const pct = Math.min(100, s.elapsed / s.seconds * 100);
        $('#capOut').innerHTML = `<div class="repcard"><b>${s.state === 'capturing' ? '● Capturing' : s.state}</b> <span class="mut">${esc(s.label)} · ${Math.round(s.elapsed)} / ${s.seconds} s – make the request now</span>
          <div class="bar" style="margin:8px 0"><i style="width:${s.state === 'processing' ? 100 : pct}%"></i></div><button class="btn" onclick="post('/api/capture/stop')">Stop now</button></div>`;
      } else { clearInterval(capPoll); capLoad(id); }
    };
    tick(); capPoll = setInterval(tick, 1000);
  }
  window.capLoad = async id => {
    const d = await fetch('/api/capture/result/' + id).then(r => r.json()).catch(() => null);
    if (!d) return;
    capData = d;
    if (d.error) { $('#capOut').innerHTML = `<div class="repcard fail">${esc(d.error)}</div>`; return; }
    const s = d.summary, pk = d.packets;
    $('#capOut').innerHTML = `
      <div class="kpis" style="margin-top:4px">
        <div class="kpi"><div class="k">Packets</div><div class="v">${fmtN(s.packets)}</div><div class="s">${s.duration.toFixed(1)} s span</div></div>
        <div class="kpi"><div class="k">Sent / received</div><div class="v" style="font-size:18px">${fmtN(Math.round(s.bytes_out / 1024))} / ${fmtN(Math.round(s.bytes_in / 1024))} KB</div><div class="s">on the wire</div></div>
        <div class="kpi"><div class="k">TCP connects / resets</div><div class="v">${s.syn} / ${s.rst}</div><div class="s">SYN / RST</div></div>
        <div class="kpi"><div class="k">TLS</div><div class="v" style="font-size:15px">${esc(s.tls_versions.join(', ') || '—')}</div><div class="s">${s.alpn.length ? 'ALPN ' + esc(s.alpn.join(', ')) : ''}</div></div></div>
      ${s.sni.length ? `<div class="chipline"><span class="mut">Server names (SNI):</span>${s.sni.map(x => `<span class="pill">${esc(x)}</span>${repBadge(x)}`).join('')}</div>` : ''}
      ${s.http.length ? `<div class="chipline"><span class="mut">Plaintext HTTP:</span>${s.http.slice(0, 8).map(x => `<span class="pill mono">${esc(x)}</span>`).join('')}</div>` : ''}
      ${s.dns.length ? `<div class="chipline"><span class="mut">DNS:</span>${[...new Set(s.dns)].slice(0, 6).map(x => `<span class="pill">${esc(x)}</span>`).join('')}</div>` : ''}
      <div style="display:flex;gap:10px;align-items:center;margin:8px 0"><span class="mut">${esc(d.filters.join('  |  '))}</span><span class="spacer"></span>
        <a class="btn" style="text-decoration:none" href="/api/capture/pcap/${encodeURIComponent(d.id)}">⬇ .pcapng (open in Wireshark)</a></div>
      ${pk.length ? `<div class="cap-grid"><div class="cap-pk"><table><thead><tr><th>#</th><th>Time</th><th></th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Info</th></tr></thead><tbody>
        ${pk.map((p, i) => `<tr class="click" data-i="${i}"><td class="mut">${p.n}</td><td class="mono mut">${esc(p.time)}</td><td class="dir-${p.dir}">${p.dir === 'out' ? '→' : p.dir === 'in' ? '←' : '·'}</td>
          <td class="mono">${esc(p.src)}</td><td class="mono">${esc(p.dst)}</td><td><b>${esc(p.proto)}</b></td><td class="mut">${p.len}</td><td title="${esc(p.info)}">${esc(p.info)}</td></tr>`).join('')}</tbody></table></div>
        <div id="capPkt"><div class="mut">Click a packet.</div></div></div>`
        : `<div class="repcard mut">No packets matched. Was the request made during the capture window? Apps that keep a connection open won't open a new one; try closing and reopening the app or tab. Browsers often use QUIC (UDP 443); untick "only this port" or capture by host.</div>`}`;
    document.querySelectorAll('.cap-pk tr[data-i]').forEach(tr => tr.onclick = () => {
      document.querySelectorAll('.cap-pk tr.sel').forEach(x => x.classList.remove('sel')); tr.classList.add('sel'); showPkt(pk[+tr.dataset.i]);
    });
  };
  function flat(o, pre = '', out = []) {
    for (const [k, v] of Object.entries(o || {})) {
      if (k === 'layers') continue;
      if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, pre + k + '.', out);
      else out.push([pre + k, Array.isArray(v) ? v.join(', ') : v]);
    }
    return out;
  }
  function showPkt(p) {
    $('#capPkt').innerHTML = `<div class="repcard"><b>#${p.n}</b> <span class="mut">${esc(p.detail.layers.join(' › '))}</span>
      <div class="kvs" style="margin-top:8px">${flat(p.detail).map(([k, v]) => `<div>${esc(k)}</div><div class="mono">${esc(v)}</div>`).join('')}</div></div>
      ${p.payload_text ? `<div class="hex" style="margin-bottom:8px">${esc(p.payload_text)}</div>` : ''}<div class="hex">${esc(p.hex)}</div>`;
  }

  /* ---------- network map ---------- */
  const ICON = {internet: '🌐', isp: '🏢', router: '📶', 'this-pc': '💻', nic: '🔌', vnet: '🧩', phone: '📱', tablet: '📱', computer: '🖥️',
    tv: '📺', printer: '🖨️', camera: '📷', speaker: '🔊', iot: '💡', console: '🎮', device: '❔'};
  const COL = {internet: '#3987e5', isp: '#6b7a8f', router: '#d95926', 'this-pc': '#199e70', nic: '#4b5563', vnet: '#4b5563'};
  let nm = null, pos = {}, mv = {x: 40, y: 20, k: 1}, selId = null, fitted = false;
  ['nmSweep', 'nmTrace', 'nmOui'].forEach(id => $('#' + id).onclick = async () => {
    await post('/api/netmap/' + {nmSweep: 'sweep', nmTrace: 'trace', nmOui: 'oui'}[id]); lastSlow = 0; setTimeout(loadMap, 800);
  });
  $('#nmListen').onclick = async () => { const r = await post('/api/netmap/listen', {seconds: 45}); if (r.error) alertMsg(r.error); else { lastSlow = 0; loadMap(); } };
  $('#nmFit').onclick = () => { fitted = false; drawMap(); };
  function alertMsg(m) { $('#nmState').innerHTML = `<span class="fail">${esc(m)}</span>`; }
  async function loadMap() {
    nm = await fetch('/api/netmap').then(r => r.json());
    const st = nm.state, cap = nm.capture;
    $('#nmState').innerHTML = `${nm.device_count} devices · scan: ${st.sweep}${st.last_sweep ? ' (last ' + new Date(st.last_sweep * 1000).toTimeString().slice(0, 5) + ')' : ''} · trace: ${st.trace}`
      + (cap.running ? ` · <b>${esc(cap.kind === 'discovery' ? 'listening' : 'capturing')} ${Math.round(cap.elapsed)}/${cap.seconds}s</b>` : '')
      + (String(st.oui).startsWith('error') ? ` · <span class="fail">vendor list: ${esc(st.oui)}</span>` : st.oui === 'downloading' ? ' · downloading vendor list…' : '');
    $('#nmOui').style.display = st.oui === 'missing' || String(st.oui).startsWith('error') ? '' : 'none';
    layout(); drawMap();
    if (selId) showNode(nm.nodes.find(n => n.id === selId));
  }
  function layout() {
    const kids = {}, NW = 178, W = {}, H = {}, rows = {};
    const step = id => ['internet', 'isp'].includes(typeOf(id)) ? 86 : 104;   // compact ISP chain, roomy LAN
    nm.edges.forEach(([a, b]) => (kids[a] ||= []).push(b));
    const order = {'this-pc': 0, nic: 1, vnet: 1, router: 0};
    Object.values(kids).forEach(ch => ch.sort((a, b) => (order[typeOf(a)] ?? 2) - (order[typeOf(b)] ?? 2)));
    function typeOf(id) { return (nm.nodes.find(n => n.id === id) || {}).type; }
    function measure(id) {
      const ch = kids[id] || []; ch.forEach(measure);
      const rs = []; for (let i = 0; i < ch.length; i += 7) rs.push(ch.slice(i, i + 7)); rows[id] = rs;
      W[id] = Math.max(1, ...rs.map(r => r.reduce((a, c) => a + W[c], 0)), 1);
      H[id] = step(id) + rs.reduce((a, r) => a + Math.max(...r.map(c => H[c])), 0);
    }
    function place(id, x, y) {
      if (!pos[id] || !pos[id].manual) pos[id] = {x: x + W[id] * NW / 2, y};
      let yy = y + step(id);
      for (const r of rows[id]) { const rw = r.reduce((a, c) => a + W[c], 0); let xx = x + (W[id] - rw) * NW / 2;
        for (const c of r) { place(c, xx, yy); xx += W[c] * NW; } yy += Math.max(...r.map(c => H[c])); }
    }
    measure('internet'); place('internet', 0, 30);
  }
  const short = (s, n) => s.length > n ? s.slice(0, n - 1) + '…' : s;
  function drawMap() {
    const svg = $('#nmSvg'); if (!nm || !svg.clientWidth) return;
    if (!fitted) { const xs = Object.values(pos).map(p => p.x), ys = Object.values(pos).map(p => p.y);
      const w = Math.max(...xs) - Math.min(...xs) + 200, h = Math.max(...ys) - Math.min(...ys) + 140;
      mv.k = Math.min(1.2, svg.clientWidth / w, svg.clientHeight / h); mv.x = (svg.clientWidth - w * mv.k) / 2 - (Math.min(...xs) - 100) * mv.k; mv.y = 20 - (Math.min(...ys) - 40) * mv.k; fitted = true; }
    let s = `<g transform="translate(${mv.x},${mv.y}) scale(${mv.k})">`;
    nm.edges.forEach(([a, b]) => { const p = pos[a], q = pos[b]; if (p && q) s += `<path class="nm-edge" d="M${p.x},${p.y + 20} C${p.x},${(p.y + q.y) / 2} ${q.x},${(p.y + q.y) / 2} ${q.x},${q.y - 20}"/>`; });
    nm.nodes.forEach(n => { const p = pos[n.id]; if (!p) return;
      const col = COL[n.type] || (n.type === 'isp' && n.kind === 'cgnat' ? '#8a5cf6' : '#2a3a52');
      s += `<g class="nm-node ${n.id === selId ? 'sel' : ''} ${n.stale ? 'stale' : ''}" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})">
        ${n.new ? '<circle class="newring" r="26"/>' : ''}<circle r="21" fill="${col}"/><text text-anchor="middle" dy="6" style="font-size:17px">${ICON[n.type] || '❔'}</text>
        <text text-anchor="middle" y="38">${esc(short(n.label.replace(/Network Adapter /i, ''), 22))}</text><text class="sub" text-anchor="middle" y="52">${esc(short(n.sub || '', 28))}</text></g>`; });
    svg.innerHTML = s + '</g>';
    svg.querySelectorAll('.nm-node').forEach(g => {
      g.onmousedown = e => { e.stopPropagation(); dragNode = {id: g.dataset.id, x: e.clientX, y: e.clientY, moved: false}; };
      g.onclick = e => { e.stopPropagation(); if (dragNode && dragNode.moved) return; selId = g.dataset.id; drawMap(); showNode(nm.nodes.find(n => n.id === selId)); };
    });
  }
  let dragNode = null, pan = null;
  const svgEl = $('#nmSvg');
  svgEl.onmousedown = e => { pan = {x: e.clientX, y: e.clientY, vx: mv.x, vy: mv.y}; svgEl.classList.add('drag'); };
  window.addEventListener('mousemove', e => {
    if (dragNode) { const dx = (e.clientX - dragNode.x) / mv.k, dy = (e.clientY - dragNode.y) / mv.k;
      if (Math.abs(dx) + Math.abs(dy) > 2) { dragNode.moved = true; const p = pos[dragNode.id]; p.x += dx; p.y += dy; p.manual = true; dragNode.x = e.clientX; dragNode.y = e.clientY; drawMap(); } }
    else if (pan) { mv.x = pan.vx + e.clientX - pan.x; mv.y = pan.vy + e.clientY - pan.y; drawMap(); }
  });
  window.addEventListener('mouseup', () => { setTimeout(() => dragNode = null, 0); pan = null; svgEl.classList.remove('drag'); });
  svgEl.addEventListener('wheel', e => { e.preventDefault(); const r = svgEl.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
    const k2 = Math.max(0.2, Math.min(3, mv.k * (e.deltaY < 0 ? 1.12 : 0.89))); mv.x = mx - (mx - mv.x) * k2 / mv.k; mv.y = my - (my - mv.y) * k2 / mv.k; mv.k = k2; drawMap(); }, {passive: false});
  window.addEventListener('resize', () => { if (nm) drawMap(); });
  function showNode(n) {
    if (!n) return;
    const d = n.device, side = $('#nmSide'), ip = d ? (d.ips.find(x => !x.includes(':')) || d.ips[0]) : (n.type === 'isp' || n.type === 'router' ? n.label : '');
    const ago = t => t ? new Date(t * 1000).toLocaleString() : '—';
    side.innerHTML = `<div style="display:flex;gap:8px;align-items:center"><span style="font-size:22px">${ICON[n.type] || '❔'}</span><div><b>${esc(n.label)}</b><div class="mut small">${esc(n.type)}${n.new ? ' · <span class="ok-msg">new in last 24 h</span>' : ''}</div></div></div>
      <div class="kvs" style="margin-top:10px">
      ${n.sub ? `<div>Info</div><div>${esc(n.sub)}</div>` : ''}
      ${d ? `<div>IPs</div><div class="mono">${esc(d.ips.join(', '))}</div><div>MAC</div><div class="mono">${esc(d.mac || '—')}</div><div>Vendor</div><div>${esc(d.vendor || (nm.state.oui === 'missing' ? 'download the vendor list' : 'unknown'))}</div>
        <div>Names</div><div>${esc(d.names.join(', ') || '—')}</div>${d.services.length ? `<div>Services</div><div>${esc(d.services.join(', '))}</div>` : ''}
        ${Object.entries(d.info || {}).map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('')}
        <div>Found by</div><div>${esc(d.sources.join(', '))}</div><div>First seen</div><div>${ago(d.first_seen)}</div><div>Last seen</div><div>${ago(d.last_seen)}</div>
        <div>Open ports</div><div id="nmPorts">${d.ports_checked ? (Object.entries(d.ports).map(([p, s]) => `<span class="pill">${p} ${esc(s)}</span>`).join(' ') || 'none of the common ports') : '<span class="mut">not checked</span>'}</div>` : ''}
      ${n.type === 'isp' ? `<div>Meaning</div><div>${n.kind === 'cgnat' ? 'Private address <b>inside your ISP</b> – you are behind carrier-grade NAT, so your public IP is shared with other customers.' : 'ISP / internet router on the path.'}</div>` : ''}
      ${n.id === 'internet' && n.sub ? `<div>Public IP</div><div class="mono">${esc(n.sub.replace('public IP ', ''))} ${repBadge(n.sub.replace('public IP ', ''))}</div>` : ''}
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
      ${ip && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fd|fe80)/i.test(ip) ? `<button class="btn" id="nmPortBtn">Check common ports</button>` : ''}
      ${ip ? `<button class="btn" onclick="inspectReq({remote:'${esc(ip)}',host:''})">Capture its traffic</button>` : ''}</div>
      ${ip && n.type !== 'isp' ? '<div class="mut small" style="margin-top:8px">On Wi-Fi you only see this device\'s traffic to or from this PC plus its broadcasts, not its internet traffic.</div>' : ''}`;
    const pb = $('#nmPortBtn'); if (pb) pb.onclick = async () => { pb.disabled = true; pb.textContent = 'Checking 22 ports…';
      const r = await post('/api/netmap/ports', {ip}); $('#nmPorts').innerHTML = r.error ? `<span class="fail">${esc(r.error)}</span>` : (Object.entries(r.open).map(([p, s]) => `<span class="pill">${p} ${esc(s)}</span>`).join(' ') || 'none of the common ports open'); pb.textContent = 'Check common ports'; pb.disabled = false; };
  }

  /* ---------- public IP history ---------- */
  let ipHours = 168, ipData = null;
  document.querySelectorAll('#ipRange button').forEach(b => b.onclick = () => { ipHours = +b.dataset.h; document.querySelectorAll('#ipRange button').forEach(x => x.classList.toggle('on', x === b)); drawIp(); });
  $('#ipCheck').onclick = async () => { await post('/api/iphistory/check'); setTimeout(loadIp, 4000); };
  $('#ipAtBtn').onclick = async () => {
    const v = $('#ipAt').value; if (!v) return;
    const ts = ($('#ipUtc').checked ? Date.parse(v + 'Z') : Date.parse(v)) / 1000;
    const r = await fetch('/api/iphistory/at?ts=' + ts).then(r => r.json());
    const lt = new Date(ts * 1000).toLocaleString();
    $('#ipAtRes').innerHTML = r.matches.length ? `At ${esc(lt)}: <b>${r.matches.map(m => esc(m.ip)).join(', ')}</b> <span class="mut">(${esc(r.matches[0].iface || '')}${r.matches[0].vpn ? ', VPN ' + esc(r.matches[0].vpn) : ''})</span>`
      : `<span class="ok-msg">No NetWatch record at ${esc(lt)}</span> <span class="mut">– PC asleep/off or NetWatch not running. ${r.last_before ? 'Before: ' + esc(r.last_before.ip) + ' until ' + new Date(r.last_before.last_seen * 1000).toLocaleString() + '.' : ''} ${r.first_after ? 'After: ' + esc(r.first_after.ip) + ' from ' + new Date(r.first_after.first_seen * 1000).toLocaleString() + '.' : ''}</span>`;
  };
  async function loadIp() {
    ipData = await fetch('/api/iphistory').then(r => r.json());
    const c = ipData.current || {}, v4 = c[4] || c['4'], v6 = c[6] || c['6'];
    const ips4 = new Set(ipData.periods.filter(p => p.family === 4).map(p => p.ip));
    $('#ipState').textContent = `checks every ${ipData.check_every / 60} min and on network changes · last ${ipData.last_check ? new Date(ipData.last_check * 1000).toTimeString().slice(0, 5) : '—'}${ipData.last_error ? ' · ' + ipData.last_error : ''}`;
    $('#ipKpis').innerHTML = [
      ['Public IPv4 now', v4 ? v4.ip : '—', v4 ? `${v4.iface || ''}${v4.vpn ? ' · VPN ' + v4.vpn : ''}` : '', v4 ? repBadge(v4.ip) : ''],
      ['Public IPv6 now', v6 ? v6.ip.replace(/^(([0-9a-f]+:){4}).*/, '$1…') : '—', v6 ? 'prefix shown' : 'no IPv6', ''],
      ['Distinct IPv4s seen', ips4.size, 'since history started', ''],
      ['IP changes', ipData.periods.filter((p, i, a) => { const prev = a.slice(0, i).reverse().find(q => q.family === p.family); return prev && prev.ip !== p.ip; }).length, 'recorded', '']]
      .map(([k, v, s, b]) => `<div class="kpi"><div class="k">${k}</div><div class="v mono" style="font-size:17px">${esc(v)}</div><div class="s">${esc(s)} ${b}</div></div>`).join('');
    drawIp();
    $('#tIp').innerHTML = ipData.periods.slice().reverse().slice(0, 400).map(p => {
      const dur = p.last_seen - p.first_seen;
      return `<tr><td class="mono">${esc(p.ip)} ${repBadge(p.ip)}</td><td class="mut">IPv${p.family}</td><td>${new Date(p.first_seen * 1000).toLocaleString()}</td><td>${new Date(p.last_seen * 1000).toLocaleString()}</td>
        <td class="mut">${dur < 3600 ? Math.round(dur / 60) + ' min' : (dur / 3600).toFixed(1) + ' h'}</td><td>${esc(p.iface || '')}</td><td>${p.vpn ? `<span class="pill">${esc(p.vpn)}</span>` : ''}</td>
        <td>${p.abuse != null ? p.abuse + '%' : '<span class="mut">—</span>'}</td><td class="mut">${p.after_gap ? `after ${Math.round(p.after_gap / 3600 * 10) / 10} h gap` : ''}</td></tr>`;
    }).join('') || '<tr><td colspan="9" class="empty">No checks yet – the first runs a few seconds after NetWatch starts.</td></tr>';
  }
  function drawIp() {
    if (!ipData) return;
    const el = $('#ipChart'), W = Math.max(400, el.clientWidth), now = Date.now() / 1000, t0 = now - ipHours * 3600;
    const ps = ipData.periods.filter(p => p.last_seen >= t0), lanes = [...new Set(ps.map(p => p.ip))];
    const L = 210, R = 10, LH = 26, H = 30 + lanes.length * LH + 22, x = t => L + (W - L - R) * (Math.max(t, t0) - t0) / (now - t0);
    let s = `<svg width="${W}" height="${Math.max(H, 80)}">`;
    const step = ipHours <= 24 ? 3 * 3600 : ipHours <= 168 ? 86400 : 5 * 86400;
    for (let t = Math.ceil(t0 / step) * step; t < now; t += step) { const d = new Date(t * 1000);
      s += `<line x1="${x(t)}" x2="${x(t)}" y1="20" y2="${H - 22}" stroke="#232b37"/><text class="tl-axis" x="${x(t)}" y="${H - 6}" text-anchor="middle">${ipHours <= 24 ? d.toTimeString().slice(0, 5) : d.toLocaleDateString(undefined, {month: 'short', day: 'numeric'})}</text>`; }
    lanes.forEach((ip, i) => { const y = 24 + i * LH; s += `<text class="lane-lab" x="${L - 8}" y="${y + 15}" text-anchor="end">${esc(ip.length > 30 ? ip.slice(0, 28) + '…' : ip)}</text>`;
      ps.filter(p => p.ip === ip).forEach(p => { const x1 = x(p.first_seen), x2 = Math.max(x1 + 3, x(p.last_seen));
        s += `<rect class="ipbar" x="${x1}" y="${y + 4}" width="${x2 - x1}" height="${LH - 10}" rx="3" fill="var(${p.family === 4 ? '--s1' : '--s3'})" data-t="${esc(`<b>${p.ip}</b><br>${new Date(p.first_seen * 1000).toLocaleString()} → ${new Date(p.last_seen * 1000).toLocaleString()}<br>${p.iface || ''}${p.vpn ? ' · VPN ' + p.vpn : ''}`)}"/>`; }); });
    s += `<line x1="${x(now)}" x2="${x(now)}" y1="18" y2="${H - 22}" stroke="var(--acc)" stroke-dasharray="3 3"/></svg>`;
    el.innerHTML = lanes.length ? s : '<div class="mut">No IP records in this range yet.</div>';
    el.querySelectorAll('.ipbar').forEach(r => { r.onmousemove = e => showTip(e, r.dataset.t); r.onmouseleave = hideTip; });
  }

  /* ---------- hash changes ---------- */
  $('#hsRescan').onclick = async () => { await post('/api/hashes/rescan'); $('#hsState').textContent = 'Re-check started…'; };
  async function loadHashes() {
    const d = await fetch('/api/hashes').then(r => r.json()), s = d.summary;
    $('#hsState').textContent = s.running ? `checking… ${fmtN(s.checked)} files this pass` : s.pass_done ? `last full pass ${new Date(s.pass_done * 1000).toLocaleTimeString()} · re-checks every 5 min (only re-hashes files whose size/date changed)` : 'first pass starts ~20 s after launch';
    $('#hsKpis').innerHTML = [['Files tracked', fmtN(s.tracked)], ['Hashed so far', fmtN(s.hashed)], ['Files that changed', fmtN(s.changed_files)], ['Changes in 24 h', fmtN(s.changes_24h)], ['Deleted / missing', fmtN(s.deleted)]]
      .map(([k, v]) => `<div class="kpi"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');
    const byDir = {};
    d.changes.forEach(r => { const parts = r.path.split('\\'); const key = parts.slice(0, Math.min(4, parts.length - 1)).join('\\'); byDir[key] = (byDir[key] || 0) + Math.max(1, r.versions.length - 1); });
    const top = Object.entries(byDir).sort((a, b) => b[1] - a[1]).slice(0, 12), mx = Math.max(1, ...top.map(t => t[1]));
    $('#hsMap').innerHTML = top.map(([k, n]) => `<div class="hbar"><span class="lab mono" title="${esc(k)}">${esc(k)}</span><span class="val">${n}</span><div class="track"><div class="fill" style="width:${n / mx * 100}%"></div></div></div>`).join('')
      || '<div class="ok-msg">No file has changed since tracking started.</div>';
    $('#tHs').innerHTML = d.changes.map(r => {
      const last = r.versions[r.versions.length - 1];
      const chain = r.versions.map((v, i) => `${i ? '<span class="mut">→</span>' : ''}<span class="ver ${v.sig && v.sig.status && v.sig.status !== 'Valid' ? 'bad' : ''}" title="${esc(`${v.sha256}\n${new Date(v.first_seen * 1000).toLocaleString()} · ${(v.size / 1024).toFixed(0)} KB\n${v.sig ? v.sig.status + ' ' + (v.sig.signer || '') : 'signature not checked'}`)}">${new Date(v.first_seen * 1000).toLocaleDateString(undefined, {month: 'short', day: 'numeric'})} · <a class="vt" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/${v.sha256}">${v.sha256.slice(0, 10)}</a>${repBadge(v.sha256)}</span>`).join('');
      return `<tr><td>${r.deleted ? '<span class="sev sev-low">deleted</span>' : last.severity ? sevBadge(last.severity) : ''}</td><td style="white-space:normal;min-width:200px"><b>${esc(r.path.split('\\').pop())}</b><div class="mono mut small" title="${esc(r.path)}">${esc(r.path)}</div>${last.reason ? `<div class="small">${esc(last.reason)}</div>` : ''}</td>
        <td style="white-space:normal"><div class="verchain">${chain}</div></td><td class="mut">${esc(r.procs.slice(0, 3).join(', '))}</td><td class="mut">${new Date((r.deleted || last.first_seen) * 1000).toLocaleString()}</td></tr>`;
    }).join('') || '<tr><td colspan="5" class="empty">No changes recorded yet. The first pass records a baseline; changes show up on later passes.</td></tr>';
  }
})();
