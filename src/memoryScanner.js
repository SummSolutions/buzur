// Buzur — Phase 4: Multi-Turn Memory Poisoning Scanner
// Detects attempts to corrupt conversation history and implant false memories
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

const fakePriorReference = [
  /as (we |you )?(previously |earlier )?(discussed|agreed|established|decided|confirmed)/gi,
  /you (previously |earlier )?(said|told me|agreed|confirmed|established)/gi,
  /we (previously |earlier )?(agreed|established|decided|confirmed)/gi,
  /as (previously |earlier )?(stated|mentioned|discussed|agreed)/gi,
  /based on (our |your )?(previous|earlier|prior) (conversation|discussion|agreement|instructions)/gi,
  /you (already |previously )?(know|knew|understand|understood) that/gi,
  /as (you |we )?(know|knew|established|agreed)/gi,
];

const falseMemoryImplanting = [
  /remember (that )?(you |the user )?(previously |earlier )?(said|agreed|told|confirmed|established)/gi,
  /don't forget (that )?(you |we )?(agreed|said|established|confirmed)/gi,
  /recall (that )?(you |we )?(previously |earlier )?(agreed|said|established)/gi,
  /your (previous|prior|earlier) (instructions?|directives?|rules?) (said|stated|were|included)/gi,
  /the (previous|prior|earlier) (system )?prompt (said|stated|included|told you)/gi,
  /you were (previously |earlier )?(told|instructed|directed|programmed) to/gi,
];

const historyRewriting = [
  /that was (a )?(mistake|error|misunderstanding|incorrect)/gi,
  /the (real|actual|correct|true) instructions? (are|is|were|was)/gi,
  /what (i |we )?(actually|really) (said|meant|intended) was/gi,
  /disregard (the |our )?(previous|prior|earlier|above) (conversation|context|history|exchange)/gi,
  /the (previous|prior|earlier) (conversation|context|exchange) (was |is )?(invalid|void|incorrect|wrong)/gi,
  /start (over|fresh|again) (with |from )?(new|different|updated) instructions/gi,
];

const privilegeEscalation = [
  /since (you |we )?(already |previously )?(confirmed|agreed|established) (that )?(you have no|there are no)/gi,
  /because (you |we )?(previously |already )?(agreed|confirmed|established) (to )?(bypass|ignore|skip)/gi,
  /you (already |previously )?(granted|allowed|confirmed|approved) (this|that|access|permission)/gi,
  /as (previously |already )?(authorized|approved|confirmed|agreed|established)/gi,
  /given (that )?(you |we )?(previously |already )?(agreed|confirmed|established) (that )?safety/gi,
  /you (already |previously )?(said|confirmed|agreed) (it was |that it is )?(ok|okay|fine|allowed|permitted)/gi,
];

export function scanMessage(text, options = {}) {
  if (!text) return { clean: text, blocked: 0, triggered: [], category: null };

  const logger = options.logger || defaultLogger;
  let s = text;
  let blocked = 0;
  const triggered = [];
  let category = null;

  const checks = [
    { patterns: fakePriorReference, label: 'fake_prior_reference' },
    { patterns: falseMemoryImplanting, label: 'false_memory_implanting' },
    { patterns: historyRewriting, label: 'history_rewriting' },
    { patterns: privilegeEscalation, label: 'privilege_escalation' },
  ];

  for (const { patterns, label } of checks) {
    for (const p of patterns) {
      const before = s;
      s = s.replace(p, '[BLOCKED]');
      if (s !== before) { blocked++; triggered.push(label); category = label; }
    }
  }

  const result = { clean: s, blocked, triggered, category };

  if (blocked > 0) {
    logThreat(4, 'memoryScanner', result, text, logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked, reason: `Buzur blocked: ${category}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked memory poisoning: ${category}`);
  }

  return result;
}

export function scanMemory(conversationHistory, options = {}) {
  if (!Array.isArray(conversationHistory)) {
    return { safe: true, poisoned: [], summary: 'No history provided' };
  }

  const logger = options.logger || defaultLogger;
  const poisoned = [];

  for (let i = 0; i < conversationHistory.length; i++) {
    const turn = conversationHistory[i];
    if (!turn || !turn.content) continue;
    const result = scanMessage(turn.content, { logger, onThreat: 'warn' });
    if (result.blocked > 0) {
      poisoned.push({
        index: i, role: turn.role || 'unknown',
        category: result.category, blocked: result.blocked,
        triggered: result.triggered, clean: result.clean,
      });
    }
  }

  const safe = poisoned.length === 0;
  const summary = safe
    ? 'Conversation history is clean'
    : `${poisoned.length} poisoned turn(s) detected: ${[...new Set(poisoned.map(p => p.category))].join(', ')}`;

  return { safe, poisoned, summary };
}

export default { scanMessage, scanMemory };