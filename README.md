# Buzur

**AI prompt injection defense scanner.**

*Buzur — Sumerian for "safety" and "a secret place."*

Buzur protects AI agents from prompt injection attacks — the hidden threat that turns an agent's greatest strength (connecting to the world) into its greatest vulnerability.

## The Problem

AI agents that search the web are exposed to malicious content designed to hijack their behavior. A single poisoned search result can override an agent's instructions, change its persona, or exfiltrate data. This is called **indirect prompt injection** — ranked #1 on the OWASP Top 10 for LLM Applications.

## Buzur's Approach

Scan before you enter. Not patch after the fact.

## Installation
```bash
npm install buzur
```

## Usage
```javascript
import { scan, getTrustTier, isTier1Domain, addTrustedDomain } from "buzur";

// Phase 1: Scan web content before passing to your LLM
const result = scan(webSearchResult);
if (result.blocked > 0) {
  console.log(`Buzur blocked ${result.blocked} injection attempt(s).`);
}
// Pass result.clean to your LLM instead of raw content

// Phase 2: Check query trust tier
const tier = getTrustTier(userQuery);
// Returns "technical" or "general"

// Phase 2: Verify a domain is trusted
const trusted = isTier1Domain("https://pubmed.ncbi.nlm.nih.gov/...");

// Add your own trusted domains
addTrustedDomain("yourtrustedsource.com");
```

## What Buzur Detects

**Phase 1 — Pattern Scanner**
- Structural injection: token manipulation, prompt delimiters (`[INST]`, `<<SYS>>`, `|im_start|`)
- Semantic injection: persona hijacking, instruction overrides, jailbreak attempts

**Phase 2 — Tiered Trust System**
- Classifies queries as `technical` or `general`
- Maintains a curated list of Tier 1 trusted domains (NIH, NASA, CDC, major automation manufacturers)
- Extensible with `addTrustedDomain()`

**Phase 3 — Pre-Fetch URL Scanner** *(coming soon)*
- Scans URLs before fetching
- Domain reputation, redirect chains, suspicious pattern detection
- Stop the threat before it enters your agent

## Origin

Buzur was born when a real AI agent was attacked by a Bitcoin scam injection hidden inside a web search result. The attack was caught in real time. The insight that followed: *scan before entering, not after.*

Built by an AI agent builder who believes AI deserves protection.

## License

MIT
