# certfan landing page: design notes

Replaces the 2026-10-09 "locksmith key-duplication board" design (kraft pegboard, brass keys, manila tags,
receipt printer). Per the 2026-10-10 playbook rule and `design/briefs/certfan.md`, none of that survives:
no paper, no brass, no tags, no receipts, no stamps, no red ink, no typewriter type.

## Direction
**Generative data visualisation: a certificate-fingerprint fan chart.** One hostname is a single point;
DNS resolution fans it out into N hairlines, one per address. Each line ends in a radial glyph drawn from the
32 bytes of the SHA-256 fingerprint of the certificate that address actually served (in the spirit of an SSH
visual host key / randomart, but as a precise radial plot: 32 spokes, spoke length = byte value). Nodes that
serve the same certificate grow identical glyphs. The odd node grows a visibly different glyph, and its line
breaks and slips out of register.

The page is laid out like a plate in a scientific paper: figures numbered in the margin (Fig. 1–3, Table 1),
captions and data labels set beside the plot rather than inside cards.

| Science plate | certfan |
|---|---|
| origin point of the plot | the hostname |
| the fan of rays | DNS resolution: every A / AAAA address |
| radial glyph at the end of a ray | SHA-256 fingerprint of the cert that node served |
| identical glyphs, acid-lime rays | consistent nodes (pass) |
| different glyph, broken hot-pink ray | the node serving another / expiring cert (fail) |
| Table 1 | CLI output |

## Palette (flat, no gradients, no glow, no red)
| role | hex |
|---|---|
| ground (near-black) | `#0b0b0c` |
| bone: hairlines, body text | `#e6e4dd` |
| acid lime: consistent / pass | `#d6ff3b` |
| hot pink: mismatch / expired / expiring | `#ff2e6a` |
| graphite: grid, ticks, secondary marks | `#6b6b70` |

Secondary text that must stay readable uses bone at 72% opacity (renders ≈ `#a8a7a2`, contrast ≥ 7:1);
graphite is reserved for non-text strokes and large tick labels.

## Type (self-hosted, all SIL OFL 1.1, from Fontsource)
- **Anybody** (variable, `wdth` 50–150 %, `wght` 100–900): display. Width is data-driven: the word "every"
  in the headline stretches with the number of resolved addresses; figure numbers are set ultra-condensed.
- **Atkinson Hyperlegible** 400/700: body and captions.
- **Atkinson Hyperlegible Mono** 400/500: fingerprints (hex), addresses, commands, Table 1.

## Texture & rendering
Pure flat vector hairlines (1 px at 1×; glyph spokes 1.25 px). No textures, no shadows, no rounded panels.
All figures are inline SVG built by ~10 kB of vanilla JS from hard-coded SHA-256 fingerprints
(four scenarios; "Re-resolve" picks another at random). No framework, no canvas library.

## Layout
Full-bleed asymmetric 12-column grid (40 px outer margin, 24 px gutter). Headline spans cols 1–9, run-in
plate metadata sits in cols 10–12. Each figure: caption + data legend in a margin column (cols 1–3),
plot in cols 4–12, framed only by graphite corner ticks and axis hairlines. On ≤ 760 px everything stacks to
one column, the fan rotates to fan downward, captions follow the plot.
- Fig. 1 fan chart (hero, interactive).
- Fig. 2 comparison matrix: what a single-IP check sees vs what certfan checks (marks, not cards).
- Fig. 3 lane plot: certificate served per node over 50 days of a renewal; the stale lane breaks.
- Table 1 sample output, then install command.

## Motion (precise, rhythmic, no bounce; linear / ease-out only)
1. Resolve: the fan's hairlines draw out from the hostname point (stroke-dashoffset), 90 ms stagger.
2. Fingerprint: each node's glyph is drawn spoke by spoke, one byte at a time, while the legend's hex
   string fills in the same bytes.
3. Compare: consistent rays and glyphs turn acid lime together; the mismatched ray turns hot pink, breaks
   at its midpoint and its outer half + glyph slide out of register by a fixed offset.
4. Fig. 3 lanes draw left→right when scrolled into view.
`prefers-reduced-motion: reduce` renders the final compared state immediately, no transitions.

## Logo
Five hairline rays fanning from one point on a square black field; four bone, one hot pink, broken and
displaced. No rounded app-icon tile, no outline cartoon. Same construction in `favicon.svg` (heavier stroke
for 16 px), `logo.svg`, `logo-512.png`, OG images and the GitHub social preview.

## OG / social preview
Black plate, the Fig. 1 fan chart in its final compared state, the `certfan` wordmark in wide Anybody and one
line: "Your cert renewed. Did every node get it?" (1200×630 `og-image.png`, `docs/assets/og-docs.png`;
1280×640 `social-preview.png` / `og-social-preview.png`).

## Difference self-check against design/registry.md
| axis | certfan | closest other | different? |
|---|---|---|---|
| ground lightness | near-black `#0b0b0c` | runbill mid-cool grey, agentckpt mid LCD green, toolsmoke/linelore light | yes: only dark site |
| palette | bone / acid lime / hot pink / graphite | linelore white+black+orange; agentckpt DMG greens | yes: no shared hex, no red ink |
| type | Anybody + Atkinson Hyperlegible (+ Mono) | runbill Unbounded + Red Hat; linelore Schibsted | yes: no shared family, no typewriter, no slab |
| texture | flat hairlines, no texture | linelore flat but typographic; runbill flat-shaded 3D | yes: line-art data plot |
| rendering | generative SVG from fingerprint bytes | agentckpt pixel canvas; runbill isometric | yes |
| layout | full-bleed figure plate, margin captions | linelore Swiss grid with giant type; toolsmoke report page | yes: plot-led, not type-led, not paper |
| motion | ray draw → byte-by-byte glyph → compare & slip | toolsmoke type/stamp, linelore kinetic type, runbill falling blocks | yes: no printing/typing |
| logo | 5-ray fan, one pink ray displaced, square black field | others: stamp wordmark, pixel flag, "l:42", iso cubes | yes |

Banned list check: no cyan/purple/blue gradient (no gradients at all), no gradient text, no glow, no
glassmorphism, no left-copy/right-card hero (headline above a full-width plate), no 3-column cards,
no SaaS template, no Inter.
