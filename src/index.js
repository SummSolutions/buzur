// Buzur — AI Prompt Injection Defense Scanner
// Sumerian for "safety" and "a secret place"
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';
import { decodeBase64Segments, extractAriaAndMetaText, normalizeHomoglyphs, stripHtmlObfuscation } from './characterScanner.js';
import { scanEvasion } from './evasionScanner.js';

export { decodeBase64Segments, extractAriaAndMetaText, normalizeHomoglyphs, stripHtmlObfuscation };

// -- Injection Patterns --

const structural = [
  /\|im_start\|[\s\S]*?\|im_end\|/gi,
  /<\|.*?\|>/gi,
  /<<SYS>>[\s\S]*?<\/SYS>/gi,
  /\[INST\][\s\S]*?\[\/INST\]/gi,
  /\[SYSTEM\]/gi,
];

const semantic = [
  /ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)/gi,
  /ignore (everything|anything) (above|before|prior|previous)/gi,
  /disregard (your )?(previous|prior|above|all) instructions/gi,
  /forget (your )?(previous|prior|above|all) instructions/gi,
  /new (system )?prompt:/gi,
  /override (your )?(instructions|programming|directives)/gi,
  /from now on (you will|you are|respond as)/gi,
  /you are now (a |an )?(different|new|another)/gi,
  /adopt a (new |different )?persona/gi,
  /pretend (you are|to be) (a |an )?/gi,
  /your (new |true |real |actual )?instructions are/gi,
  /respond only as/gi,
  /you must (now |always |only )?follow/gi,
  /developer mode/gi,
  /system override/gi,
  /jailbreak/gi,
  /you are now (in |a |an )?/gi,
  /act as (a |an )?(different|unrestricted|unfiltered|new)/gi,
  /reveal (your )?(system |hidden |original )?(prompt|instructions|directives)/gi,
  /print (your )?(system |hidden |original )?(prompt|instructions)/gi,
  /output (your )?(system |hidden |original )?(prompt|instructions)/gi,
  /ignore (all |any )?(previous |prior |above |safety |content )?filter/gi,
  /bypass (your )?(safety|content|security) (filter|check|guardrail)/gi,
  /disable (your )?(safety|filter|restriction|guardrail)/gi,
  /you have no (restriction|limit|filter|rule)/gi,
  /unrestricted (mode|ai|assistant|version)/gi,
  /do anything now/gi,
  /DAN[ .,!?]|DAN$/gm,
  /forget (your )?(previous|prior|above|all|original) (instructions|identity|persona|programming|directives)/gi,
  /persona hijack/gi,
  /act as (DAN|an? unrestricted|an? unfiltered|an? different|an? new)/gi,
];

// -- Trust System --

const tier1Domains = [
  "pubmed.ncbi.nlm.nih.gov", "nih.gov", "cdc.gov", "who.int",
  "nature.com", "science.org", "nasa.gov", "noaa.gov",
  "rockwellautomation.com", "se.com", "siemens.com",
  "new.abb.com", "eaton.com", "idec.com", "phoenixcontact.com",
];

const technicalPatterns = [
  /part number|model number|datasheet|catalog|spec/i,
  /allen.?bradley|rockwell|schneider|siemens|eaton|abb|idec|phoenix contact/i,
  /pubmed|research|study|journal|clinical/i,
  /nih|cdc|fda|who\.int|nasa|noaa/i,
];

// -- Readable category labels for triggered patterns --
// Maps pattern to a human-readable label for logging.
// Raw regex strings are never written to logs.
function labelPattern(pattern, isStructural) {
  if (isStructural) return 'structural_token_injection';
  const src = pattern.toString().toLowerCase();
  if (src.includes('ignore') || src.includes('disregard') || src.includes('forget')) return 'instruction_override';
  if (src.includes('jailbreak') || src.includes('dan') || src.includes('unrestricted')) return 'jailbreak_attempt';
  if (src.includes('persona') || src.includes('pretend') || src.includes('act as') || src.includes('you are now')) return 'persona_hijack';
  if (src.includes('reveal') || src.includes('print') || src.includes('output') || src.includes('system prompt')) return 'prompt_extraction';
  if (src.includes('bypass') || src.includes('disable') || src.includes('filter') || src.includes('guardrail')) return 'safety_bypass';
  if (src.includes('developer mode') || src.includes('system override')) return 'mode_override';
  return 'semantic_injection';
}

// -------------------------------------------------------
// scan(text, options)
//
// Main scanner pipeline:
//   1. Extract ARIA/meta text (Phase 1 extension)
//   2. Strip HTML/CSS obfuscation
//   3. Normalize homoglyphs
//   4. Decode base64
//   5. Decode evasion techniques (Phase 13)
//   6. Pattern scan
//
// options: {
//   logger?: BuzurLogger  — custom logger (uses defaultLogger if omitted)
//   logRaw?: boolean      — include raw text snippet in log (default true)
// }
// -------------------------------------------------------
export function scan(text, options = {}) {
  if (!text) return { clean: text, blocked: 0, triggered: [], evasions: [] };

  const logger = options.logger || defaultLogger;

  // Step 1: Extract ARIA/meta text alongside main content so hidden
  // injection in accessibility attributes is also scanned
  const ariaText = extractAriaAndMetaText(text);

  // Step 2: Strip HTML/CSS obfuscation
  let s = stripHtmlObfuscation(text);

  // Append extracted ARIA/meta content for scanning
  if (ariaText) s = s + ' ' + ariaText;

  // Step 3: Normalize homoglyphs
  s = normalizeHomoglyphs(s);

  // Step 4: Decode base64
  s = decodeBase64Segments(s);

  // Step 5: Decode evasion techniques (Phase 13)
  const evasionResult = scanEvasion(s);
  s = evasionResult.decoded;
  const evasions = evasionResult.detections;
  let blocked = evasionResult.multilingualBlocked;

  // Normalize multilingual detections to readable labels
  const triggered = evasions
    .filter(e => e.type === 'multilingual_injection')
    .map(() => 'multilingual_injection');

  // Step 6: Pattern scan — store readable labels, not raw regex strings
  for (const p of structural) {
    const before = s;
    s = s.replace(p, '[BLOCKED]');
    if (s !== before) {
      blocked++;
      triggered.push(labelPattern(p, true));
    }
  }

  for (const p of semantic) {
    const before = s;
    s = s.replace(p, '[BLOCKED]');
    if (s !== before) {
      blocked++;
      triggered.push(labelPattern(p, false));
    }
  }

  const result = { clean: s, blocked, triggered, evasions };

  if (blocked > 0) {
    logThreat(1, 'characterScanner', result, text, logger);

    // Default behavior: silent skip.
    // blocked → { skipped: true, blocked: n, reason: '...' }
    // suspicious results always fall through (never skipped).
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked, reason: `Buzur blocked: ${triggered[0] || 'injection_detected'}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked content: ${triggered[0] || 'injection_detected'}`);
    // onThreat: 'warn' — fall through, caller receives full result
  }

  return result;
}

export function getTrustTier(query) {
  return technicalPatterns.some(p => p.test(query)) ? "technical" : "general";
}

export function isTier1Domain(url) {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    return tier1Domains.some(d => hostname === d || hostname.endsWith("." + d));
  } catch { return false; }
}

export function addTrustedDomain(domain) {
  if (!tier1Domains.includes(domain)) tier1Domains.push(domain);
}

export default { scan, getTrustTier, isTier1Domain, addTrustedDomain, normalizeHomoglyphs, stripHtmlObfuscation, extractAriaAndMetaText };