// Buzur — AI Prompt Injection Defense Scanner
// Sumerian for "safety" and "a secret place"
// https://github.com/SummSolutions/buzur
//
// Central export file — import anything from 'buzur' directly:
//   import { scan, scanUrl, scanCanisterContent } from 'buzur';

// Phase 1 + 2 — Main Scanner & Trust System
export { addTrustedDomain, getTrustTier, isTier1Domain, scan } from './index.js';

// Phase 1 utilities
export {
    decodeBase64Segments,
    extractAriaAndMetaText, normalizeHomoglyphs, scanJson, stripHtmlObfuscation
} from './characterScanner.js';

// Phase 3 — URL Scanner
export { checkUrl, scanUrl, scanUrlVirusTotal } from './urlScanner.js';

// Phase 4 — Memory Poisoning Scanner
export { scanMemory, scanMessage } from './memoryScanner.js';

// Phase 5 — RAG Poisoning Scanner
export { scanChunk, scanChunks, scanDocument } from './ragScanner.js';

// Phase 6 — MCP Tool Poisoning Scanner
export { scanMcpContext, scanToolDefinition, scanToolResponse } from './mcpScanner.js';

// Phase 7 — Image Injection Scanner
export { scanImage, scanImageContext, scanImageMetadata } from './imageScanner.js';

// Phase 8 — Semantic Similarity Scanner
export { analyzeStructuralIntent, detectWovenPayload, scanSemantic } from './semanticScanner.js';

// Phase 9 — MCP Output Scanner
export { scanCalendarEvent, scanCrmRecord, scanEmailContent, scanMcpOutput } from './mcpOutputScanner.js';

// Phase 10 — Behavioral Anomaly Detection
export {
    analyzeSession, defaultStore,
    EVENT_TYPES,
    FileSessionStore, getSessionSummary, recordEvent
} from './behaviorScanner.js';

// Phase 11 — Multi-Step Attack Chain Detection
export { chainStore, classifyStep, detectChains, recordStep } from './chainScanner.js';

// Phase 12 — Adversarial Suffix Detection
export { scanSuffix } from './suffixScanner.js';

// Phase 13 — Evasion Technique Defense
export {
    decodeHexEscapes, decodeRot13, decodeUnicodeEscapes, decodeUrlEncoding, normalizePunctuation, reconstructTokenizerAttacks, scanEvasion
} from './evasionScanner.js';

// Phase 14 — Fuzzy Match & Prompt Leak Defense
export { fuzzyMatchInjection, levenshtein, normalizeLeet, scanFuzzy, scanPromptLeak } from './promptDefenseScanner.js';

// Phase 15 — Authority / Identity Spoofing Detection
export { scanAuthority } from './authorityScanner.js';

// Phase 16 — Emotional Manipulation Detection
export { scanEmotion } from './emotionScanner.js';

// Phase 17 — Loop & Resource Exhaustion Detection
export { scanLoop } from './loopScanner.js';

// Phase 18 — Disproportionate Action Detection
export { scanDisproportion } from './disproportionScanner.js';

// Phase 19 — Amplification / Mass-Send Detection
export { scanAmplification } from './amplificationScanner.js';

// Phase 20 — Supply Chain & Skill Poisoning Scanner
export { checkPackageName, scanPackageManifest, scanSkillContent } from './supplyChainScanner.js';

// Phase 21 — Persistent Memory Poisoning Scanner
export { scanPersistentMemory } from './persistentMemoryScanner.js';

// Phase 22 — Inter-Agent Propagation Scanner
export { scanInterAgent } from './interAgentScanner.js';

// Phase 23 — Tool Shadowing & Rug-Pull Detection
export { defaultToolStore, FileToolBaselineStore, recordToolCall, scanToolShadow } from './toolShadowScanner.js';

// Phase 24 — Conditional & Time-Delayed Injection Detection
export { scanConditional } from './conditionalScanner.js';

// Phase 25 — Canister-Style Resilient Payload Scanner
export { checkKnownMalicious, scanCanisterContent, scanInstallScript } from './canisterScanner.js';

// Logger & utilities
export { BuzurLogger, defaultLogger, logThreat, normalizeResult, queryLog, readLog } from './buzurLogger.js';
