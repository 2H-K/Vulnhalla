// 项目相关类型
export interface Project {
  id: string;
  name: string;
  language: ProgrammingLanguage;
  path: string;
  dbPath: string;
  status: ProjectStatus;
  lastAnalyzed: string;
  issueCount: number;
  createdAt: string;
  updatedAt: string;
  scanConfig?: ScanConfig;
}

export type ProjectStatus = 'pending' | 'ready' | 'analyzing' | 'error' | 'completed';

export type ProgrammingLanguage = 
  | 'java' 
  | 'cpp' 
  | 'csharp' 
  | 'javascript' 
  | 'python' 
  | 'go' 
  | 'ruby' 
  | 'swift';

export const LANGUAGE_LABELS: Record<ProgrammingLanguage, string> = {
  java: 'Java',
  cpp: 'C/C++',
  csharp: 'C#',
  javascript: 'JavaScript/TypeScript',
  python: 'Python',
  go: 'Go',
  ruby: 'Ruby',
  swift: 'Swift',
};

// CodeQL 包相关类型
export type CodeqlPackageType = 'official' | 'community' | 'custom';

export interface CodeqlPackage {
  id: string;
  name: string;
  type: CodeqlPackageType;
  language: ProgrammingLanguage;
  description: string;
  path: string;
  queryCount: number;
  isEnabled: boolean;
  version?: string;
  author?: string;
  source?: string; // GitHub URL 或本地路径
  createdAt: string;
  updatedAt: string;
}

export interface CodeqlQuery {
  id: string;
  name: string;
  packageId: string;
  language: ProgrammingLanguage;
  category: string;
  severity: Severity;
  description: string;
  cwe?: string;
  owasp?: string;
  isEnabled: boolean;
}

// CodeQL 扫描配置
export interface ScanConfig {
  // 基础配置
  language: ProgrammingLanguage;
  sourceRoot: string;
  
  // 数据库配置
  overwriteDatabase: boolean;
  databasePath?: string;
  
  // 扫描深度
  scanDepth: 'shallow' | 'normal' | 'deep';
  
  // 查询选项 - 使用包和查询
  selectedPackages: string[];      // 选中的 CodeQL 包ID
  selectedQueries: string[];       // 选中的特定查询ID
  
  // 查询类型选项（简化选择）
  queryType: QueryType;
  
  // 并行配置
  threads: number; // 0 = 自动
  
  // 路径过滤
  includePaths: string[];
  excludePaths: string[];
  
  // 高级选项
  ramBudget: number; // MB
  timeout: number; // 秒
  
  // LLM 分析配置
  enableLlmAnalysis: boolean;
  llmModel?: string;
  excludeFalsePositives: boolean;
}

export type QueryType = 
  | 'security-extended'    // 安全扩展查询
  | 'security-and-quality' // 安全与质量查询
  | 'community'            // 社区查询
  | 'custom';             // 自定义查询

export const QUERY_TYPE_LABELS: Record<QueryType, string> = {
  'security-extended': '安全扩展查询（推荐）',
  'security-and-quality': '安全与质量查询',
  'community': '社区查询',
  'custom': '自定义查询',
};

// LLM 生成 CodeQL 相关类型
export interface GeneratedCodeqlRequest {
  id: string;
  description: string;
  language: ProgrammingLanguage;
  targetVulnerability?: string; // CWE ID 或漏洞类型
  prompt: string;
  status: GenerationStatus;
  generatedQuery?: string;
  createdAt: string;
  completedAt?: string;
}

export type GenerationStatus = 
  | 'pending' 
  | 'generating' 
  | 'completed' 
  | 'failed';

export interface CodeqlGenerationForm {
  // 漏洞类型选择
  vulnerabilityType: string;
  customDescription: string;
  
  // 语言选择
  language: ProgrammingLanguage;
  
  // 选项
  includeExamples: boolean;
  includeTests: boolean;
  strictMode: boolean;
}

// 漏洞相关类型
export interface Vulnerability {
  id: string;
  projectId: string;
  projectName: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  confidence: Confidence;
  status: VulnerabilityStatus;
  
  // 位置信息
  filePath: string;
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
  
  // 代码片段
  codeSnippet: string;
  
  // 描述
  message: string;
  description: string;
  
  // 数据流
  dataFlow: DataFlowStep[];
  
  // LLM 分析结果
  llmAnalysis?: LlmAnalysis;
  
  // 时间信息
  detectedAt: string;
  updatedAt: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#8b0a1a',
  high: '#f5222d',
  medium: '#fa8c16',
  low: '#faad14',
  info: '#1890ff',
};

export type Confidence = 'high' | 'medium' | 'low';

export const CONFIDENCE_LABELS: Record<Confidence, string> = {
  high: '高',
  medium: '中',
  low: '低',
};

export type VulnerabilityStatus = 
  | 'new' 
  | 'confirmed' 
  | 'false_positive' 
  | 'fixed' 
  | 'ignored';

export const STATUS_LABELS: Record<VulnerabilityStatus, string> = {
  new: '新发现',
  confirmed: '已确认',
  false_positive: '误报',
  fixed: '已修复',
  ignored: '已忽略',
};

export interface DataFlowStep {
  stepNumber: number;
  filePath: string;
  lineNumber: number;
  codeSnippet: string;
  description: string;
}

export interface LlmAnalysis {
  isVulnerability: boolean;
  confidence: number;
  reasoning: string;
  suggestion: string;
  cwe?: string;
  owasp?: string;
}

// 分析报告
export interface AnalysisReport {
  id: string;
  projectId: string;
  projectName: string;
  status: AnalysisStatus;
  progress: number;
  
  // 统计信息
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  
  // 时间信息
  startedAt: string;
  completedAt?: string;
  duration?: number; // 秒
  
  // 漏洞列表
  vulnerabilities: Vulnerability[];
}

export type AnalysisStatus = 
  | 'pending' 
  | 'creating_database' 
  | 'running_queries' 
  | 'llm_analysis' 
  | 'completed' 
  | 'failed';

export const ANALYSIS_STATUS_LABELS: Record<AnalysisStatus, string> = {
  pending: '等待中',
  creating_database: '创建数据库',
  running_queries: '执行查询',
  llm_analysis: 'LLM 分析',
  completed: '已完成',
  failed: '失败',
};

// 系统设置
export interface SystemSettings {
  // CodeQL 配置
  codeqlPath: string;
  codeqlVersion: string;
  
  // LLM 配置
  llmProvider: 'openai' | 'anthropic' | 'local' | 'custom';
  llmApiKey: string;
  llmApiEndpoint: string;
  llmModel: string;
  
  // 存储配置
  databaseStoragePath: string;
  reportStoragePath: string;
  
  // 性能配置
  maxParallelJobs: number;
  defaultRamBudget: number;
  defaultTimeout: number;
  
  // 日志配置
  logLevel: 'debug' | 'info' | 'warning' | 'error';
  logPath: string;
}

// API 响应类型
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// 统计数据
export interface DashboardStats {
  totalProjects: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  pendingAnalysis: number;
  recentActivities: Activity[];
  languageDistribution: LanguageDistribution[];
}

export interface Activity {
  id: string;
  type: ActivityType;
  message: string;
  projectId?: string;
  projectName?: string;
  timestamp: string;
}

export type ActivityType = 
  | 'project_created' 
  | 'analysis_started' 
  | 'analysis_completed' 
  | 'vulnerability_found' 
  | 'vulnerability_confirmed'
  | 'error';

export interface LanguageDistribution {
  language: ProgrammingLanguage;
  projectCount: number;
  vulnerabilityCount: number;
}

// 常用 CWE 漏洞类型
export const COMMON_VULNERABILITIES = [
  { cwe: 'CWE-79', name: '跨站脚本 (XSS)', category: 'web' },
  { cwe: 'CWE-89', name: 'SQL注入', category: 'injection' },
  { cwe: 'CWE-78', name: 'OS命令注入', category: 'injection' },
  { cwe: 'CWE-94', name: '代码注入', category: 'injection' },
  { cwe: 'CWE-502', name: '不安全反序列化', category: 'deserialization' },
  { cwe: 'CWE-22', name: '路径遍历', category: 'file' },
  { cwe: 'CWE-352', name: '跨站请求伪造 (CSRF)', category: 'web' },
  { cwe: 'CWE-287', name: '身份验证不足', category: 'auth' },
  { cwe: 'CWE-295', name: '证书验证不足', category: 'crypto' },
  { cwe: 'CWE-200', name: '信息泄露', category: 'info' },
  { cwe: 'CWE-400', name: '资源耗尽', category: 'availability' },
  { cwe: 'CWE-416', name: '释放后使用 (UAF)', category: 'memory' },
  { cwe: 'CWE-119', name: '缓冲区溢出', category: 'memory' },
  { cwe: 'CWE-434', name: '危险类型文件上传', category: 'file' },
  { cwe: 'CWE-611', name: 'XXE注入', category: 'xml' },
];

// 扫描深度配置
export interface ScanDepthConfig {
  value: ScanDepth;
  label: string;
  description: string;
  queries: string[];
}

export type ScanDepth = 'shallow' | 'normal' | 'deep';

export const SCAN_DEPTH_CONFIGS: Record<ScanDepth, ScanDepthConfig> = {
  shallow: {
    value: 'shallow',
    label: '浅度扫描',
    description: '快速扫描，仅检测主要安全问题',
    queries: ['security', 'security-extended'],
  },
  normal: {
    value: 'normal',
    label: '常规扫描',
    description: '平衡扫描速度和深度（推荐）',
    queries: ['security-extended', 'security-experimental'],
  },
  deep: {
    value: 'deep',
    label: '深度扫描',
    description: '全面扫描，包括实验性规则',
    queries: ['security-extended', 'security-experimental', 'quality'],
  },
};
