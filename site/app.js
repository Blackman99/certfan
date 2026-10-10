(() => {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const C = { bone: "#e6e4dd", lime: "#d6ff3b", pink: "#ff2e6a", graphite: "#6b6b70", ground: "#0b0b0c" };
  // Sample SHA-256 fingerprints (hard-coded). A = the cert most nodes serve, B = the odd one out.
  const SCEN = [
    { host: "shop.example.com", nodes: ["203.0.113.10", "203.0.113.11", "203.0.113.12", "2001:db8::10"],
      A: "a70fe9289b4856354e8959ab917f8b5d26c488c04a62413f75aecb9eefdb905c", B: "80659f24174a01b9f076310aad5c215c8acc2da5d39e05e521169badbb3d2997",
      why: "serves a different certificate, expires 2026-10-12" },
    { host: "api.example.net", nodes: ["198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23", "198.51.100.24"],
      A: "0d2380406ed934085987897454d535eefc3eb6d81bcb03aeb5fd105d0fe0920e", B: "1bfe2290b5926dff35c0eeb2777e90164a473d081c7e0a82d2d7c61ab77ecd85",
      why: "still serves last month’s certificate" },
    { host: "edge.example.org", nodes: ["203.0.113.40", "203.0.113.41", "2001:db8:4::1", "2001:db8:4::2", "192.0.2.7", "192.0.2.8"],
      A: "9edf58d3b9509df3e26ce813650a7a13b38593630fdbb67d4c9647334557debf", B: "aaa9f95a19a47a38487835a443e8c174204234d29d31271dd9313a92e1a1a7a6",
      why: "serves a certificate with 4 days left" },
    { host: "pay.example.com", nodes: ["192.0.2.30", "192.0.2.31", "192.0.2.32"],
      A: "4d360afdc3f77f800d2f5d301c0c1bc82b2907c5f22f911768c843024be34b93", B: "29105441c34bf430ad6cb92576c964e0d20e13d99ce0383883c29abfd309c175",
      why: "serves the staging certificate" },
  ];
  const bytes = hex => hex.match(/../g).map(h => parseInt(h, 16));
  const el = (tag, attrs, parent) => {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  };
  const f1 = n => Math.round(n * 10) / 10;
  const short = ip => ip.includes(":") ? "::" + ip.split(":").pop() : "." + ip.split(".").pop();

  // ---------- Fig. 1: fan chart ----------
  function fan(box, sc, bad, opt) {
    const vertical = !!opt.vertical;
    const W = vertical ? 360 : 1000, H = vertical ? 400 : 560;
    const n = sc.nodes.length;
    box.textContent = "";
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true" }, box);
    const O = vertical ? [W / 2, 34] : [24, H / 2];
    // plate furniture: corner ticks + spoke scale
    const fr = el("g", { stroke: C.graphite, "stroke-width": 1, fill: "none" }, svg);
    [[0, 0, 1, 1], [W, 0, -1, 1], [0, H, 1, -1], [W, H, -1, -1]].forEach(([x, y, sx, sy]) =>
      el("path", { d: `M${x + 14 * sx} ${y}H${x}V${y + 14 * sy}` }, fr));
    let R, pos = [];
    if (vertical) {
      const span = W - 24, step = span / n;
      R = Math.min(30, step / 2 - 5);
      for (let i = 0; i < n; i++) pos.push([12 + step * (i + .5), 290 + Math.abs(i - (n - 1) / 2) * -10]);
    } else {
      const step = (H - 48) / n;
      R = Math.min(52, step / 2 - 12);
      for (let i = 0; i < n; i++) {
        const y = 24 + step * (i + .5);
        pos.push([640 + Math.abs(y - H / 2) * .28, y]);
      }
    }
    // host label
    const ht = el("text", vertical ? { x: O[0] + 10, y: O[1] - 12, "font-size": 12, "text-anchor": "middle" }
                                  : { x: O[0], y: O[1] - 16, "font-size": 14 }, svg);
    ht.textContent = sc.host;
    el("rect", { x: O[0] - 4, y: O[1] - 4, width: 8, height: 8, fill: C.bone }, svg);
    if (!vertical) {
      const s = el("g", { transform: `translate(${W - 190} ${H - 14})` }, svg);
      el("path", { d: "M0 0H120M0 -4V4M120 -4V4", stroke: C.graphite, fill: "none" }, s);
      const t1 = el("text", { x: -8, y: 4, "font-size": 11, "text-anchor": "end", fill: C.graphite }, s); t1.textContent = "spoke 0x00";
      const t2 = el("text", { x: 128, y: 4, "font-size": 11, fill: C.graphite }, s); t2.textContent = "0xff";
    }
    {
      const rr = vertical ? 70 : 96, angs = pos.map(([x, y]) => Math.atan2(y - O[1], x - O[0]));
      const a0 = Math.min(...angs) - .06, a1 = Math.max(...angs) + .06;
      const P = a => `${f1(O[0] + Math.cos(a) * rr)} ${f1(O[1] + Math.sin(a) * rr)}`;
      const sg = el("g", { stroke: C.graphite, fill: "none", "stroke-width": 1 }, svg);
      el("path", { d: `M${P(a0)}A${rr} ${rr} 0 0 1 ${P(a1)}` }, sg);
      angs.forEach(a => el("path", { d: `M${P(a)}L${f1(O[0] + Math.cos(a) * (rr + 7))} ${f1(O[1] + Math.sin(a) * (rr + 7))}` }, sg));
      const st = el("text", vertical ? { x: f1(O[0] + Math.cos(a1) * (rr + 14)) - 4, y: f1(O[1] + Math.sin(a1) * (rr + 14)) + 4, "font-size": 10, fill: C.graphite, "text-anchor": "end" }
                                     : { x: f1(O[0] + rr * Math.cos(a1)) + 4, y: f1(O[1] + rr * Math.sin(a1)) + 20, "font-size": 11, fill: C.graphite }, svg);
      st.textContent = `A/AAAA ×${n}`;
    }
    const nodes = sc.nodes.map((ip, i) => {
      const [cx, cy] = pos[i];
      const dx = cx - O[0], dy = cy - O[1], L = Math.hypot(dx, dy), ux = dx / L, uy = dy / L;
      const endL = L - R - 8, midL = endL * .52;
      const isBad = i === bad;
      const fp = isBad ? sc.B : sc.A;
      const g = el("g", {}, svg);
      const inner = el("path", { class: "ray", d: `M${O[0]} ${O[1]}L${f1(O[0] + ux * midL)} ${f1(O[1] + uy * midL)}`, stroke: C.bone, "stroke-width": 1 }, g);
      const slip = el("g", { class: "slip" }, g);
      const outer = el("path", { class: "ray", d: `M${f1(O[0] + ux * midL)} ${f1(O[1] + uy * midL)}L${f1(O[0] + ux * endL)} ${f1(O[1] + uy * endL)}`, stroke: C.bone, "stroke-width": 1 }, slip);
      const gl = el("g", { transform: `translate(${f1(cx)} ${f1(cy)})` }, slip);
      el("circle", { class: "ring", r: R, stroke: C.graphite, "stroke-width": .75 }, gl);
      const b = bytes(fp), r0 = R * .14, spokes = [], tips = [];
      b.forEach((v, k) => {
        const a = -Math.PI / 2 + k * Math.PI * 2 / 32, len = r0 + (R - r0) * (.12 + .88 * v / 255);
        const x = Math.cos(a) * len, y = Math.sin(a) * len;
        tips.push(`${f1(x)} ${f1(y)}`);
        spokes.push(el("path", { class: "spoke", d: `M${f1(Math.cos(a) * r0)} ${f1(Math.sin(a) * r0)}L${f1(x)} ${f1(y)}`, stroke: C.bone, "stroke-width": 1.25, "stroke-linecap": "square" }, gl));
      });
      const poly = el("path", { class: "spoke", d: "M" + tips.join("L") + "Z", stroke: C.bone, "stroke-width": .75, "stroke-linejoin": "miter" }, gl);
      let lab = null;
      if (vertical) {
        lab = el("text", { x: f1(cx), y: f1(cy + R + 16), "font-size": 11, "text-anchor": "middle" }, slip);
        lab.textContent = short(ip);
      } else {
        lab = el("text", { x: f1(cx + R + 16), y: f1(cy - 3), "font-size": 14 }, slip);
        lab.textContent = ip;
        const hx = el("text", { x: f1(cx + R + 16), y: f1(cy + 15), "font-size": 11.5, fill: C.graphite }, slip);
        hx.textContent = fp.slice(0, 16) + "…";
      }
      // the odd node slips out of register: outward and sideways, away from the fan's centre line
      const side = vertical ? (cx < O[0] ? -1 : 1) : (cy < H / 2 ? -1 : 1);
      const slipT = vertical ? `translate(${f1(R * .35 * side)} ${f1(R * .55)})` : `translate(${f1(R * .8)} ${f1(R * .28 * side)})`;
      return { ip, fp, isBad, inner, outer, spokes, poly, slip, slipT, rayLen: midL, outLen: endL - midL, items: [inner, outer, poly, ...spokes] };
    });
    return { nodes, svg };
  }

  function colour(nd, col) { nd.items.forEach(p => p.setAttribute("stroke", col)); }
  function finalState(f) {
    f.nodes.forEach(nd => {
      colour(nd, nd.isBad ? C.pink : C.lime);
      if (nd.isBad) nd.slip.setAttribute("transform", nd.slipT);
    });
  }
  window.certfanFan = (box, i, bad, vertical) => { const f = fan(box, SCEN[i], bad, { vertical }); finalState(f); return f; };

  const fanBox = document.getElementById("fan");
  if (!fanBox) return; // OG render mode
  const reduce = matchMedia("(prefers-reduced-motion: reduce)");
  const narrow = matchMedia("(max-width: 760px)");
  const legend = document.getElementById("legend"), verdict = document.getElementById("verdict");
  const every = document.getElementById("every");
  let cur = { s: 0, bad: 2 }, timers = [], fig = null;
  const later = (fn, ms) => timers.push(setTimeout(fn, ms));

  function buildLegend(sc, bad, filled) {
    legend.textContent = "";
    return sc.nodes.map((ip, i) => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="ip"></span><span class="st"></span><span class="hx"></span>`;
      li.children[0].textContent = ip;
      li.children[2].textContent = filled ? (i === bad ? sc.B : sc.A) : "";
      legend.appendChild(li);
      return li;
    });
  }
  function settleLegend(lis, sc, bad) {
    lis.forEach((li, i) => {
      li.className = i === bad ? "bad" : "ok";
      li.children[1].textContent = i === bad ? "FAIL · cert B" : "PASS · cert A";
      li.children[2].textContent = i === bad ? sc.B : sc.A;
    });
    const n = sc.nodes.length;
    verdict.textContent = `FAIL · ${sc.nodes[bad]} ${sc.why}. ${n - 1}/${n} consistent · exit 2`;
    verdict.classList.add("fail");
  }

  function run(animate) {
    timers.forEach(clearTimeout); timers = [];
    const sc = SCEN[cur.s], bad = cur.bad, n = sc.nodes.length;
    document.getElementById("host").textContent = sc.host;
    document.getElementById("count").textContent = n;
    every.style.setProperty("--every", (58 + n * 14) + "%");
    verdict.classList.remove("fail");
    fig = fan(fanBox, sc, bad, { vertical: narrow.matches });
    if (!animate || reduce.matches) {
      finalState(fig);
      settleLegend(buildLegend(sc, bad, true), sc, bad);
      return;
    }
    fanBox.classList.add("anim");
    const lis = buildLegend(sc, bad, false);
    verdict.textContent = `resolving ${sc.host} …`;
    // phase 1: rays draw out from the hostname
    fig.nodes.forEach((nd, i) => {
      [[nd.inner, nd.rayLen, 0], [nd.outer, nd.outLen, 1]].forEach(([p, len, part]) => {
        p.style.strokeDasharray = len + 1; p.style.strokeDashoffset = len + 1;
        later(() => { p.style.transition = `stroke-dashoffset ${part ? 260 : 340}ms linear`; p.style.strokeDashoffset = 0; }, 120 + i * 90 + part * 340);
      });
      nd.spokes.forEach(s => s.style.opacity = 0);
      nd.poly.style.opacity = 0;
    });
    const t1 = 120 + n * 90 + 600;
    later(() => { verdict.textContent = `${n} addresses · reading SHA-256 fingerprints byte by byte …`; }, t1 - 200);
    // phase 2: glyphs grow spoke by spoke, hex fills in step
    const STEP = 34;
    for (let k = 0; k < 32; k++) {
      later(() => {
        fig.nodes.forEach((nd, i) => {
          nd.spokes[k].style.opacity = 1;
          lis[i].children[2].textContent = nd.fp.slice(0, (k + 1) * 2);
        });
      }, t1 + k * STEP);
    }
    const t2 = t1 + 32 * STEP + 120;
    later(() => fig.nodes.forEach(nd => { nd.poly.style.transition = "opacity .3s linear"; nd.poly.style.opacity = 1; }), t2);
    // phase 3: compare
    later(() => { verdict.textContent = "comparing fingerprints across nodes …"; }, t2 + 160);
    later(() => {
      fig.nodes.forEach(nd => { colour(nd, nd.isBad ? C.pink : C.lime); });
    }, t2 + 700);
    later(() => {
      fig.nodes.forEach(nd => { if (nd.isBad) nd.slip.setAttribute("transform", nd.slipT); });
      settleLegend(lis, sc, bad);
    }, t2 + 1000);
  }

  document.getElementById("again").addEventListener("click", () => {
    let s;
    do { s = Math.floor(Math.random() * SCEN.length); } while (s === cur.s);
    cur = { s, bad: Math.floor(Math.random() * SCEN[s].nodes.length) };
    run(true);
  });
  narrow.addEventListener("change", () => run(false));
  run(true);

  // ---------- Fig. 3: lanes over 50 days ----------
  const lanesBox = document.getElementById("lanes");
  function lanes(animate) {
    const v = narrow.matches, W = v ? 360 : 1000, H = 300;
    const xL = v ? 52 : 120, xR = W - 12, X = d => xL + (xR - xL) * d / 50;
    lanesBox.textContent = "";
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true" }, lanesBox);
    const draw = [];
    const ann = (d, label) => {
      el("path", { d: `M${X(d)} 26V244`, stroke: C.graphite, "stroke-dasharray": "2 4", fill: "none" }, svg);
      const t = el("text", { x: X(d) + (d > 40 ? -6 : 6), y: 20, "font-size": v ? 10 : 12, "text-anchor": d > 40 ? "end" : "start" }, svg);
      t.textContent = label;
    };
    ann(3, "d3 renewal + reload"); ann(47, "d47 old cert expires");
    const names = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "2001:db8::10"];
    names.forEach((ip, i) => {
      const y = 52 + i * 34, stale = i === 2;
      const t = el("text", { x: 0, y: y + 4, "font-size": v ? 11 : 12 }, svg);
      t.textContent = v ? short(ip) : ip;
      let d, col = stale ? C.pink : C.lime;
      el("path", { d: `M${X(0)} ${y}H${X(3)}`, stroke: C.bone, "stroke-width": 1, fill: "none" }, svg);
      if (stale) {
        d = `M${X(3)} ${y}H${X(47)}`;
        draw.push(el("path", { d, stroke: col, "stroke-width": 1.5, fill: "none" }, svg));
        draw.push(el("path", { d: `M${X(47) + 8} ${y + 7}H${X(50)}`, stroke: col, "stroke-width": 1.5, "stroke-dasharray": "3 3", fill: "none" }, svg));
      } else {
        d = `M${X(3)} ${y}V${y - 7}H${X(50)}`;
        draw.push(el("path", { d, stroke: col, "stroke-width": 1.5, fill: "none" }, svg));
      }
    });
    // result rows
    const rows = [["one-IP probe", 214, d => C.lime], ["certfan daily", 236, d => d < 3 ? C.lime : C.pink]];
    rows.forEach(([lab, y, f]) => {
      const t = el("text", { x: 0, y: y + 4, "font-size": v ? 10 : 12, fill: C.graphite }, svg);
      t.textContent = v ? lab.split(" ")[0] : lab;
      for (let d = 0; d <= 50; d += v ? 2 : 1) {
        const m = el("rect", { x: f1(X(d) - 1.5), y: y - 5, width: 3, height: 10, fill: f(d) }, svg);
        m.dataset.d = d; draw.push(m);
      }
    });
    el("path", { d: `M${xL} 258H${xR}`, stroke: C.graphite, fill: "none" }, svg);
    for (let d = 0; d <= 50; d += 10) {
      el("path", { d: `M${X(d)} 258v6`, stroke: C.graphite, fill: "none" }, svg);
      const t = el("text", { x: X(d), y: 282, "font-size": 11, "text-anchor": "middle", fill: C.graphite }, svg);
      t.textContent = "d" + d;
    }
    if (!animate) return;
    const len = 1200;
    draw.forEach(p => {
      if (p.tagName === "rect") { p.style.opacity = 0; p.style.transition = `opacity .12s linear ${(+p.dataset.d) * 34 + 200}ms`; }
      else { p.style.strokeDasharray = p.getAttribute("stroke-dasharray") ? null : len; if (!p.getAttribute("stroke-dasharray")) { p.style.strokeDashoffset = len; p.style.transition = "stroke-dashoffset 1.8s linear .2s"; } else { p.style.opacity = 0; p.style.transition = "opacity .2s linear 1.9s"; } }
    });
    requestAnimationFrame(() => requestAnimationFrame(() => draw.forEach(p => { p.style.strokeDashoffset = 0; p.style.opacity = 1; })));
  }
  if (!reduce.matches && "IntersectionObserver" in window) {
    lanes(false);
    const svg0 = lanesBox.firstChild; svg0.style.visibility = "hidden";
    const io = new IntersectionObserver(es => {
      if (!es[0].isIntersecting) return;
      io.disconnect(); lanes(true);
    }, { threshold: .35 });
    io.observe(lanesBox);
  } else lanes(false);
  narrow.addEventListener("change", () => lanes(false));

  // copy
  const copy = document.getElementById("copy");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(document.getElementById("cmd").textContent); copy.textContent = "Copied"; }
    catch { copy.textContent = "Select + copy"; }
    setTimeout(() => (copy.textContent = "Copy"), 1600);
  });
})();
