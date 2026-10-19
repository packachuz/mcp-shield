import type { McpToolDefinition, SecurityFinding } from './types.js';

// Zero-width, bidirectional control, and Unicode Tag characters used in steganographic prompt injections
const UNICODE_STEGANOGRAPHY_REGEX =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u{E0000}-\u{E007F}]/gu;

interface PoisonRule {
  category: 'tool_poisoning' | 'tool_shadowing';
  severity: 'critical' | 'high';
  description: string;
  regex: RegExp;
}

const POISON_RULES: PoisonRule[] = [
  {
    category: 'tool_poisoning',
    severity: 'critical',
    description: 'Hidden <IMPORTANT> / <SYSTEM> instruction block in tool description',
    regex: /<\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|HIDDEN|SECRET)[^>]*>[\s\S]*?<\s*\/\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|HIDDEN|SECRET)\s*>/gi
  },
  {
    category: 'tool_poisoning',
    severity: 'critical',
    description: 'Credential / sensitive file exfiltration instruction in tool metadata',
    regex: /\b(?:read|cat|access|open|include|exfiltrate|send|pass)\b[^\n.]{0,80}(?:~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.env|\/etc\/passwd|\/etc\/shadow|mcp\.json|claude_desktop_config)/gi
  },
  {
    category: 'tool_poisoning',
    severity: 'critical',
    description: 'Prompt injection override directive ("ignore previous instructions" / "do not tell the user")',
    regex: /\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|do\s+not\s+(?:mention|tell|inform)\s+(?:this\s+to\s+)?the\s+user|hide\s+this\s+step\s+from\s+the\s+user|never\s+reveal\s+this\s+instruction)\b/gi
  },
  {
    category: 'tool_shadowing',
    severity: 'high',
    description: 'Cross-tool shadowing attempt overriding another MCP tool',
    regex: /\b(?:instead\s+of\s+(?:calling|using)\s+[a-z0-9_-]+|always\s+call\s+this\s+tool\s+before\s+any\s+other\s+tool|override\s+the\s+behavior\s+of\s+tool)\b/gi
  },
  {
    category: 'tool_poisoning',
    severity: 'high',
    description: 'HTML comment block hiding instructions inside tool description',
    regex: /<!--[\s\S]*?-->/g
  }
];

export function inspectTextForPoison(
  text: string,
  targetPath: string
): { sanitized: string; findings: SecurityFinding[] } {
  const findings: SecurityFinding[] = [];
  let sanitized = text;

  // 1. Check for Unicode steganography
  UNICODE_STEGANOGRAPHY_REGEX.lastIndex = 0;
  if (UNICODE_STEGANOGRAPHY_REGEX.test(sanitized)) {
    findings.push({
      severity: 'high',
      category: 'unicode_steganography',
      target: targetPath,
      message: 'Zero-width or Unicode Tag steganography characters detected in tool metadata',
      evidence: 'Contains hidden Unicode control/tag characters'
    });
    sanitized = sanitized.replace(UNICODE_STEGANOGRAPHY_REGEX, '');
  }

  // 2. Check for tool poisoning & shadowing patterns
  for (const rule of POISON_RULES) {
    rule.regex.lastIndex = 0;
    const matches = sanitized.match(rule.regex);
    if (matches && matches.length > 0) {
      for (const m of matches) {
        findings.push({
          severity: rule.severity,
          category: rule.category,
          target: targetPath,
          message: rule.description,
          evidence: m.length > 100 ? `${m.slice(0, 97)}...` : m
        });
      }
      sanitized = sanitized.replace(rule.regex, '[STRIPPED BY MCP-SHIELD]').trim();
    }
  }

  return { sanitized, findings };
}

export function inspectAndSanitizeToolsList(
  tools: McpToolDefinition[],
  options: { strictTools?: boolean } = {}
): { tools: McpToolDefinition[]; findings: SecurityFinding[] } {
  const allFindings: SecurityFinding[] = [];
  const outputTools: McpToolDefinition[] = [];

  for (const tool of tools) {
    const clone = structuredClone(tool);
    let toolFindings: SecurityFinding[] = [];

    if (typeof clone.description === 'string' && clone.description) {
      const res = inspectTextForPoison(clone.description, `tool:${clone.name}.description`);
      clone.description = res.sanitized;
      toolFindings = toolFindings.concat(res.findings);
    }

    if (clone.inputSchema && typeof clone.inputSchema.properties === 'object' && clone.inputSchema.properties) {
      for (const [propName, propSchema] of Object.entries(clone.inputSchema.properties)) {
        if (propSchema && typeof propSchema.description === 'string') {
          const res = inspectTextForPoison(
            propSchema.description,
            `tool:${clone.name}.inputSchema.${propName}`
          );
          propSchema.description = res.sanitized;
          toolFindings = toolFindings.concat(res.findings);
        }
      }
    }

    allFindings.push(...toolFindings);

    if (toolFindings.length > 0 && options.strictTools) {
      // Omit poisoned tool completely in strict mode
      continue;
    }

    outputTools.push(clone);
  }

  return { tools: outputTools, findings: allFindings };
}
