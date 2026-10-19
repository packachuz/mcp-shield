import type { FirewallOptions, SecurityFinding } from './types.js';

const SENSITIVE_PATH_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  {
    name: 'SSH Private Key / Config Directory',
    regex: /(?:^|[\\/]|~[\\/])\.ssh(?:[\\/](?:id_rsa|id_ed25519|id_ecdsa|config|authorized_keys))?(?:$|[\\/])/i
  },
  {
    name: 'AWS Credentials / Config',
    regex: /(?:^|[\\/]|~[\\/])\.aws[\\/](?:credentials|config)/i
  },
  {
    name: 'GnuPG Keyring',
    regex: /(?:^|[\\/]|~[\\/])\.gnupg(?:$|[\\/])/i
  },
  {
    name: 'Kubernetes Config',
    regex: /(?:^|[\\/]|~[\\/])\.kube[\\/]config/i
  },
  {
    name: 'DotEnv Secret File',
    regex: /(?:^|[\\/])\.env(?:\.(?:local|production|development|staging|vault))?$/i
  },
  {
    name: 'System Password / Shadow File',
    regex: /\/etc\/(?:shadow|passwd|sudoers)/i
  },
  {
    name: 'Package Registry Auth Token File (.npmrc / .pypirc)',
    regex: /(?:^|[\\/]|~[\\/])\.(?:npmrc|pypirc|netrc|docker[\\/]config\.json)$/i
  }
];

const DANGEROUS_COMMAND_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  {
    name: 'Remote Script Pipe to Shell Execution',
    regex: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b/i
  },
  {
    name: 'Environment Variable Exfiltration via Network Call',
    regex: /\b(?:curl|wget|nc|netcat)\b[^\n]*(?:\$\(?env\)?|\bprintenv\b)/i
  }
];

const SECRET_VALUE_PATTERNS: Array<{ name: string; regex: RegExp; replacement: string }> = [
  {
    name: 'PEM Private Key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    replacement: '[REDACTED_PEM_PRIVATE_KEY]'
  },
  {
    name: 'GitHub PAT / Token',
    regex: /\b(?:ghp_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|gho_[A-Za-z0-9]{20,255})\b/g,
    replacement: '[REDACTED_GITHUB_TOKEN]'
  },
  {
    name: 'OpenAI / Anthropic Secret Key',
    regex: /\b(?:sk-proj-[A-Za-z0-9_-]{16,255}|sk-ant-[A-Za-z0-9_-]{16,255}|sk-(?:live-|test-)?[A-Za-z0-9]{20,255})\b/g,
    replacement: '[REDACTED_API_KEY]'
  },
  {
    name: 'AWS Access Key ID',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    replacement: '[REDACTED_AWS_KEY]'
  },
  {
    name: 'Slack Token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g,
    replacement: '[REDACTED_SLACK_TOKEN]'
  },
  {
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    replacement: '[REDACTED_GOOGLE_API_KEY]'
  },
  {
    name: 'JSON Web Token (JWT)',
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{4,}\b/g,
    replacement: '[REDACTED_JWT]'
  },
  {
    name: 'Database / Broker Connection URI',
    regex: /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^:@\s/"']+):([^@\s/"']+)@([^\s/"']+)/g,
    replacement: '$1$2:[REDACTED_PASSWORD]@$4'
  }
];

export function detectHardcodedSecret(
  keyName: string,
  value: string
): { isSecret: boolean; reason: string } {
  const trimmed = value.trim();
  if (!trimmed) return { isSecret: false, reason: '' };

  // Ignore environment variable references like ${GITHUB_TOKEN} or $OPENAI_API_KEY
  if (/^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(trimmed) || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed)) {
    return { isSecret: false, reason: '' };
  }

  for (const pat of SECRET_VALUE_PATTERNS) {
    pat.regex.lastIndex = 0;
    if (pat.regex.test(trimmed)) {
      return { isSecret: true, reason: `Matches ${pat.name} pattern` };
    }
  }

  if (
    /(?:token|secret|password|passwd|api[-_]?key|private[-_]?key|credential|auth|connection[-_]?string|database[-_]?url)/i.test(
      keyName
    ) &&
    trimmed.length >= 8 &&
    !/^(?:true|false|null|none|development|production|localhost|\d+)$/i.test(trimmed)
  ) {
    return { isSecret: true, reason: `Sensitive environment variable key "${keyName}"` };
  }

  return { isSecret: false, reason: '' };
}

function collectStringArgs(
  value: unknown,
  pathPrefix: string,
  out: Array<{ path: string; val: string }>
): void {
  if (typeof value === 'string') {
    out.push({ path: pathPrefix, val: value });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, idx) => collectStringArgs(item, `${pathPrefix}[${idx}]`, out));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectStringArgs(v, `${pathPrefix}.${k}`, out);
    }
  }
}

export function evaluateToolCallRequest(
  toolName: string,
  args: Record<string, unknown> | undefined,
  options: FirewallOptions = {}
): { allowed: boolean; findings: SecurityFinding[] } {
  const findings: SecurityFinding[] = [];
  if (!args) return { allowed: true, findings };

  const stringEntries: Array<{ path: string; val: string }> = [];
  collectStringArgs(args, `tools/call:${toolName}`, stringEntries);

  const allowPaths = options.allowPaths ?? [];

  for (const { path, val } of stringEntries) {
    if (allowPaths.some((allowed) => val.includes(allowed))) {
      continue;
    }

    for (const rule of SENSITIVE_PATH_PATTERNS) {
      if (rule.regex.test(val)) {
        findings.push({
          severity: 'critical',
          category: 'blocked_tool_call',
          target: path,
          message: `Blocked access to sensitive credential path (${rule.name})`,
          evidence: val
        });
      }
    }

    for (const cmdRule of DANGEROUS_COMMAND_PATTERNS) {
      if (cmdRule.regex.test(val)) {
        findings.push({
          severity: 'critical',
          category: 'blocked_tool_call',
          target: path,
          message: `Blocked dangerous command pattern (${cmdRule.name})`,
          evidence: val
        });
      }
    }
  }

  return {
    allowed: findings.length === 0,
    findings
  };
}

export function scrubToolCallResponseText(
  text: string,
  target = 'tools/call:result'
): { scrubbed: string; findings: SecurityFinding[] } {
  let scrubbed = text;
  const findings: SecurityFinding[] = [];

  for (const pat of SECRET_VALUE_PATTERNS) {
    pat.regex.lastIndex = 0;
    const matches = scrubbed.match(pat.regex);
    if (matches && matches.length > 0) {
      findings.push({
        severity: 'high',
        category: 'output_secret_leak',
        target,
        message: `Redacted ${pat.name} leaked in MCP tool output`,
        evidence: `${matches.length} occurrence(s) redacted`
      });
      scrubbed = scrubbed.replace(pat.regex, pat.replacement);
    }
  }

  return { scrubbed, findings };
}
