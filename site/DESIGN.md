# certfan landing page: design notes

## Reference object
A **locksmith's key-duplication board**: the perforated hardboard wall behind the counter of a key-cutting
shop, with brass blanks hanging on hooks, manila key tags tied on with red string, and a steel depth gauge the
locksmith lays across the teeth to check that a copy matches the original.

| Key shop | certfan |
|---|---|
| a hook on the board | one resolved IP address |
| the key hanging on it | the certificate that node serves |
| the key's cuts (bitting) | derived from the cert's serial / fingerprint |
| steel depth gauge laid across all keys | the comparison pass |
| tag flipped to red "WRONG CUT" | the node serving a different certificate |
| "expires" punched on the tag | notAfter |
| the paper receipt from the cutting machine | the CLI output |

## Palette (from the object)
- Pegboard hardboard `#d9c49b`, hole shadow `#8a6a3a`
- Brass blank `#b8862b`, brass highlight `#dcae4f`, nickel `#a9adae`
- Manila tag `#f3e6c4`, red string / rejection ink `#c23a22`
- Stamped ink `#2b2116` (no pure black, no gradients except the flat brass shading)

## Type
- **Alfa Slab One**: letters stamped into key blanks / shop sign.
- **Archivo Narrow**: tag and receipt type, tabular figures. No monospace; the CLI output is set like a
  thermal receipt from the cutting machine.

## Layout
Centered shop-sign title above a full-width board (not left-copy/right-card). Then a work-order slip, a ruled
workshop ledger for "how it works" (rows, not columns of cards), the receipt, an install key tag, and a footer.

## Motion (all meaningful)
1. Keys are hung on their hooks one after another and settle with a small pendulum sway.
2. The steel gauge slides down across the teeth; where cuts match, nothing happens; on the odd key the gauge
   snags, the key jolts and its tag flips to red WRONG CUT (that is the product's whole verdict).
3. "Cut again" re-randomises which node is stale.
4. Receipt prints line by line when scrolled into view.
`prefers-reduced-motion`: everything renders in its final state, no sway, no printing.

## Banned-trope self-check
No dark background, no cyan/purple, no gradient text, no glow, no glassmorphism, no left/right hero, no 3-column
feature cards, no SaaS template, no Inter, no monospace pairing. Distinct from toolsmoke (lab inspection report)
and agentckpt (film-editing bench).
