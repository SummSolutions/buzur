content = open('/home/albert/buzur/src/index.js').read()

homoglyph_block = """
// -- Homoglyph Normalizer
// Maps lookalike Unicode characters back to their ASCII equivalents
const homoglyphs = {
  '\u0430': 'a', '\u0435': 'e', '\u0456': 'i', '\u043e': 'o',
  '\u0440': 'r', '\u0441': 'c', '\u0445': 'x', '\u0443': 'y',
  '\u0392': 'B', '\u0391': 'A', '\u039F': 'O', '\u0393': 'r',
  '\u0394': 'D', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I',
  '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u03A1': 'P',
  '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
};

export function normalizeHomoglyphs(text) {
  if (!text) return text;
  return text.split('').map(c => homoglyphs[c] || c).join('');
}
"""

content = content.replace(
  'export function scan(text) {\n  if (!text) return { clean: text, blocked: 0, triggered: [] };\n  let s = text;',
  homoglyph_block + '\nexport function scan(text) {\n  if (!text) return { clean: text, blocked: 0, triggered: [] };\n  let s = normalizeHomoglyphs(text);'
)

content = content.replace(
  'export default { scan, getTrustTier, isTier1Domain, addTrustedDomain };',
  'export default { scan, getTrustTier, isTier1Domain, addTrustedDomain, normalizeHomoglyphs };'
)

open('/home/albert/buzur/src/index.js', 'w').write(content)
print("Done.")
