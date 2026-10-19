export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FindingCategory =
  | 'hardcoded_secret'
  | 'tool_poisoning'
  | 'unicode_steganography'
  | 'tool_shadowing'
  | 'unpinned_package'
  | 'blocked_tool_call'
  | 'output_secret_leak';

export interface SecurityFinding {
  severity: Severity;
  category: FindingCategory;
  target: string;
  message: string;
  evidence: string;
}

export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  envFile?: string;
  url?: string;
  [key: string]: unknown;
}

export interface McpConfigFile {
  mcpServers?: Record<string, McpServerConfig>;
  servers?: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { description?: string; [key: string]: unknown }>;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface JsonRpcMessage {
  jsonrpc: '2.0';
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface EncryptedEnvVault {
  version: 1;
  encrypted: true;
  createdAt: string;
  kdf: 'scrypt';
  kdfSaltHex: string;
  ivHex: string;
  authTagHex: string;
  ciphertextHex: string;
}

export interface FirewallOptions {
  /** Block poisoned tools completely instead of sanitizing their descriptions (default: false) */
  strictTools?: boolean;
  /** Additional file paths or patterns to allow in tools/call */
  allowPaths?: string[];
  /** Disable output secret scrubbing in tools/call responses (default: false) */
  disableOutputScrub?: boolean;
}
