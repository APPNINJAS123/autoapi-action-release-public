export interface SecretFinding {
  rule: string
  line: number
}

const RULES: Array<{ name: string; pattern: RegExp }> = [
  { name: 'private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u },
  { name: 'github-token', pattern: /\b(?:gh[opurs]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/u },
  { name: 'aws-access-key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u },
  { name: 'firecrawl-api-key', pattern: /\bfc-[A-Za-z0-9_-]{20,}\b/u },
  { name: 'openai-compatible-key', pattern: /\bsk-(?:or-v1-)?[A-Za-z0-9_-]{20,}\b/u },
  { name: 'credentialed-database-url', pattern: /\bpostgres(?:ql)?:\/\/[^\s:@]+:[^@\s]+@/u },
  { name: 'generic-secret-assignment', pattern: /\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*["'][A-Za-z0-9_./+=-]{16,}/iu },
]

export function scanTextForSecrets(content: string): SecretFinding[] {
  const findings: SecretFinding[] = []
  for (const [index, line] of content.split(/\r?\n/u).entries()) {
    for (const rule of RULES) {
      if (rule.pattern.test(line)) findings.push({ rule: rule.name, line: index + 1 })
    }
  }
  return findings
}
