#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'fs';

const f = '/home/albert/buzur/test.js';
let t = readFileSync(f, 'utf-8');
let fixes = 0;

function fixSingleLine(text, fnName) {
  const re = new RegExp(`(const\\s+\\w+\\s*=\\s*(?:await\\s+)?${fnName}\\()([^;\\n]+)(\\);)`, 'g');
  return text.replace(re, (match, prefix, args, suffix) => {
    if (match.includes('onThreat')) return match;
    if (match.includes('import')) return match;
    fixes++;
    if (args.trimEnd().endsWith('}') && args.includes('{')) {
      const lastBrace = args.lastIndexOf('}');
      const before = args.slice(0, lastBrace);
      const after = args.slice(lastBrace + 1);
      return `${prefix}${before}, onThreat: 'warn' }${after}${suffix}`;
    }
    return `${prefix}${args}, { onThreat: 'warn' }${suffix}`;
  });
}

const singleLineFns = [
  'scanAuthority', 'scanEmotion', 'scanLoop', 'scanDisproportion',
  'scanAmplification', 'scanSemantic', 'scanImage', 'scanEvasion',
  'scanToolDefinition', 'scanToolResponse',
];

for (const fn of singleLineFns) {
  t = fixSingleLine(t, fn);
}

t = t.replace(
  /(const\s+\w+\s*=\s*scanToolDefinition\(\{[\s\S]*?\}\));/g,
  (match) => {
    if (match.includes('onThreat')) return match;
    fixes++;
    return match.replace('});', "}, { onThreat: 'warn' });");
  }
);

t = t.replace(
  /(const\s+mcpPoison\w+\s*=\s*scanEmailContent\(\{[\s\S]*?\}\));/g,
  (match) => {
    if (match.includes('onThreat')) return match;
    fixes++;
    return match.replace('});', "}, { onThreat: 'warn' });");
  }
);

writeFileSync(f, t);
console.log(`Applied ${fixes} fixes`);
