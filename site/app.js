(() => {
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const rail = document.getElementById("rail"), gauge = document.getElementById("gauge");
  const verdict = document.getElementById("verdict");
  const nodes = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "2001:db8::10"];
  const certA = { fp: "51fe6357", exp: "2026-11-20", name: "A" };
  const certB = { fp: "e2a91c04", exp: "2026-10-12", name: "B" };
  const NS = "http://www.w3.org/2000/svg";

  function keySVG(fp) {
    // blade from y=78 to y=250, cuts on the right edge; depth from fingerprint hex digits
    let d = "M34 66 L34 250 L44 258 L46 250";
    const step = 26;
    for (let i = 0; i < 6; i++) {
      const depth = 4 + (parseInt(fp[i], 16) % 4) * 5;
      const y = 236 - i * step;
      d += ` L${46 + 18 - depth} ${y} L${64} ${y - 9} L${64} ${y - 16}`;
    }
    d += " L46 92 L46 66 Z";
    return `<svg viewBox="0 0 80 262" aria-hidden="true">
      <circle cx="40" cy="38" r="34" fill="#b8862b" stroke="#2b2116" stroke-width="4"/>
      <circle cx="40" cy="16" r="7" fill="#d9c49b" stroke="#2b2116" stroke-width="3"/>
      <rect x="22" y="44" width="36" height="8" rx="3" fill="#dcae4f" stroke="#2b2116" stroke-width="2"/>
      <path class="cuts" d="${d}" fill="#b8862b" stroke="#2b2116" stroke-width="4" stroke-linejoin="round"/>
      <line x1="40" y1="96" x2="40" y2="244" stroke="#2b2116" stroke-width="2" opacity=".45"/>
    </svg>`;
  }

  function build(stale) {
    rail.innerHTML = "";
    nodes.forEach((ip, i) => {
      const c = i === stale ? certB : certA;
      const el = document.createElement("div");
      el.className = "key";
      el.dataset.stale = i === stale ? "1" : "";
      el.innerHTML = `<div class="hook"></div>${keySVG(c.fp)}
        <div class="ktag"><b>${ip}</b>cert ${c.name} · exp ${c.exp}<br><span class="st">${i === stale ? "WRONG CUT" : "MATCH"}</span></div>`;
      rail.appendChild(el);
    });
  }

  function finish() {
    const bad = rail.querySelector('[data-stale="1"]');
    bad.classList.remove("hung");
    void bad.offsetWidth;
    bad.classList.add("wrong");
    verdict.textContent = `FAIL · ${bad.querySelector("b").textContent} serves a different certificate · exit 2`;
    verdict.classList.add("fail");
  }

  let timers = [];
  function run() {
    timers.forEach(clearTimeout); timers = [];
    verdict.classList.remove("fail");
    verdict.textContent = "shop.example.com · resolving 4 addresses…";
    const stale = Math.floor(Math.random() * nodes.length);
    build(stale);
    const keys = [...rail.children];
    if (reduce) { keys.forEach(k => k.classList.add("hung")); finish(); return; }
    keys.forEach((k, i) => timers.push(setTimeout(() => k.classList.add("hung"), 200 + i * 260)));
    timers.push(setTimeout(() => {
      verdict.textContent = "comparing cuts…";
      gauge.classList.remove("run"); void gauge.offsetWidth; gauge.classList.add("run");
    }, 1500));
    timers.push(setTimeout(finish, 3100));
  }
  document.getElementById("again").addEventListener("click", run);
  run();

  // receipt prints when it scrolls into view
  const r = document.getElementById("receipt");
  if (!reduce && "IntersectionObserver" in window) {
    r.classList.add("printing");
    const io = new IntersectionObserver(es => {
      if (!es[0].isIntersecting) return;
      io.disconnect();
      [...r.children].forEach((p, i) => setTimeout(() => p.classList.add("on"), i * 140));
    }, { threshold: .4 });
    io.observe(r);
  }

  const copy = document.getElementById("copy");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(document.getElementById("cmd").textContent); copy.textContent = "Copied"; }
    catch { copy.textContent = "Select & copy"; }
    setTimeout(() => (copy.textContent = "Copy"), 1600);
  });
})();
