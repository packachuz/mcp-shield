export {
  parseDotEnv,
  formatDotEnv,
  encryptEnvVault,
  decryptEnvVault,
  loadSecretsFromSources
} from './core/env-loader.js';

export {
  inspectTextForPoison,
  inspectAndSanitizeToolsList
} from './core/poison-detector.js';

export {
  detectHardcodedSecret,
  evaluateToolCallRequest,
  scrubToolCallResponseText
} from './core/call-guard.js';

export { auditMcpJsonString } from './commands/audit.js';
export { migrateMcpConfigObject } from './commands/migrate.js';
export {
  processClientToServerMessage,
  processServerToClientMessage,
  runStdioFirewallProxy
} from './commands/wrap.js';

export type {
  EncryptedEnvVault,
  FindingCategory,
  FirewallOptions,
  JsonRpcMessage,
  McpConfigFile,
  McpServerConfig,
  McpToolDefinition,
  SecurityFinding,
  Severity
} from './core/types.js';
