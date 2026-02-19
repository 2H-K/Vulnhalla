import type {
  Project,
  ScanConfig,
  Vulnerability,
  AnalysisReport,
  SystemSettings,
  ApiResponse,
  PaginatedResponse,
  DashboardStats,
  CodeqlPackage,
  CodeqlQuery,
  GeneratedCodeqlRequest,
  ProgrammingLanguage,
} from '../types';

// API Base URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

// helper function for API calls
async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit
): Promise<ApiResponse<T>> {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `HTTP Error: ${response.status}`,
      };
    }

    return {
      success: true,
      data: data,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error',
    };
  }
}

// ==================== Projects API ====================

export const projectsApi = {
  // Get all projects
  async list(params?: {
    language?: string;
    status?: string;
    search?: string;
    page?: number;
    pageSize?: number;
  }): Promise<ApiResponse<PaginatedResponse<Project>>> {
    const searchParams = new URLSearchParams();
    if (params?.language) searchParams.set('language', params.language);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.search) searchParams.set('search', params.search);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.pageSize) searchParams.set('pageSize', String(params.pageSize));

    const query = searchParams.toString();
    return fetchApi(`/projects${query ? `?${query}` : ''}`);
  },

  // Get single project
  async get(id: string): Promise<ApiResponse<Project>> {
    return fetchApi(`/projects/${id}`);
  },

  // Create new project
  async create(data: {
    name: string;
    language: string;
    path: string;
    scanConfig?: ScanConfig;
  }): Promise<ApiResponse<Project>> {
    return fetchApi('/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Update project
  async update(
    id: string,
    data: Partial<Project>
  ): Promise<ApiResponse<Project>> {
    return fetchApi(`/projects/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  // Delete project
  async delete(id: string): Promise<ApiResponse<void>> {
    return fetchApi(`/projects/${id}`, {
      method: 'DELETE',
    });
  },

  // Start analysis
  async startAnalysis(
    projectId: string,
    config: ScanConfig
  ): Promise<ApiResponse<AnalysisReport>> {
    return fetchApi(`/projects/${projectId}/analyze`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  },

  // Get analysis status
  async getAnalysisStatus(projectId: string): Promise<ApiResponse<AnalysisReport>> {
    return fetchApi(`/projects/${projectId}/analysis`);
  },

  // Cancel analysis
  async cancelAnalysis(projectId: string): Promise<ApiResponse<void>> {
    return fetchApi(`/projects/${projectId}/analysis/cancel`, {
      method: 'POST',
    });
  },
};

// ==================== Vulnerabilities API ====================

export const vulnerabilitiesApi = {
  // List vulnerabilities
  async list(params?: {
    projectId?: string;
    severity?: string;
    status?: string;
    page?: number;
    pageSize?: number;
  }): Promise<ApiResponse<PaginatedResponse<Vulnerability>>> {
    const searchParams = new URLSearchParams();
    if (params?.projectId) searchParams.set('projectId', params.projectId);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.pageSize) searchParams.set('pageSize', String(params.pageSize));

    const query = searchParams.toString();
    return fetchApi(`/vulnerabilities${query ? `?${query}` : ''}`);
  },

  // Get single vulnerability
  async get(id: string): Promise<ApiResponse<Vulnerability>> {
    return fetchApi(`/vulnerabilities/${id}`);
  },

  // Update vulnerability status
  async updateStatus(
    id: string,
    status: string,
    reason?: string
  ): Promise<ApiResponse<Vulnerability>> {
    return fetchApi(`/vulnerabilities/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status, reason }),
    });
  },

  // Batch update status
  async batchUpdateStatus(
    ids: string[],
    status: string
  ): Promise<ApiResponse<void>> {
    return fetchApi('/vulnerabilities/batch-status', {
      method: 'PUT',
      body: JSON.stringify({ ids, status }),
    });
  },

  // Export vulnerabilities
  async export(format: 'json' | 'csv' | 'sarif', params?: {
    projectId?: string;
    severity?: string;
  }): Promise<Blob> {
    const searchParams = new URLSearchParams();
    searchParams.set('format', format);
    if (params?.projectId) searchParams.set('projectId', params.projectId);
    if (params?.severity) searchParams.set('severity', params.severity);

    const response = await fetch(
      `${API_BASE_URL}/vulnerabilities/export?${searchParams.toString()}`
    );
    return response.blob();
  },
};

// ==================== Reports API ====================

export const reportsApi = {
  // List reports
  async list(params?: {
    projectId?: string;
    status?: string;
    page?: number;
    pageSize?: number;
  }): Promise<ApiResponse<PaginatedResponse<AnalysisReport>>> {
    const searchParams = new URLSearchParams();
    if (params?.projectId) searchParams.set('projectId', params.projectId);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.pageSize) searchParams.set('pageSize', String(params.pageSize));

    const query = searchParams.toString();
    return fetchApi(`/reports${query ? `?${query}` : ''}`);
  },

  // Get report
  async get(id: string): Promise<ApiResponse<AnalysisReport>> {
    return fetchApi(`/reports/${id}`);
  },

  // Delete report
  async delete(id: string): Promise<ApiResponse<void>> {
    return fetchApi(`/reports/${id}`, {
      method: 'DELETE',
    });
  },
};

// ==================== Settings API ====================

export const settingsApi = {
  // Get settings
  async get(): Promise<ApiResponse<SystemSettings>> {
    return fetchApi('/settings');
  },

  // Update settings
  async update(data: Partial<SystemSettings>): Promise<ApiResponse<SystemSettings>> {
    return fetchApi('/settings', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  // Test CodeQL connection
  async testCodeql(): Promise<ApiResponse<{ version: string; path: string }>> {
    return fetchApi('/settings/test-codeql', {
      method: 'POST',
    });
  },

  // Test LLM connection
  async testLlm(): Promise<ApiResponse<{ success: boolean; message: string }>> {
    return fetchApi('/settings/test-llm', {
      method: 'POST',
    });
  },
};

// ==================== Dashboard API ====================

export const dashboardApi = {
  // Get dashboard statistics
  async getStats(): Promise<ApiResponse<DashboardStats>> {
    return fetchApi('/dashboard/stats');
  },

  // Get recent activities
  async getActivities(limit?: number): Promise<ApiResponse<{ items: any[] }>> {
    const params = limit ? `?limit=${limit}` : '';
    return fetchApi(`/dashboard/activities${params}`);
  },
};

// ==================== CodeQL Packages API ====================

export const codeqlPackagesApi = {
  // Get all packages
  async list(params?: {
    type?: 'official' | 'community' | 'custom';
    language?: ProgrammingLanguage;
    search?: string;
  }): Promise<ApiResponse<CodeqlPackage[]>> {
    const searchParams = new URLSearchParams();
    if (params?.type) searchParams.set('type', params.type);
    if (params?.language) searchParams.set('language', params.language);
    if (params?.search) searchParams.set('search', params.search);

    const query = searchParams.toString();
    return fetchApi(`/codeql/packages${query ? `?${query}` : ''}`);
  },

  // Get single package
  async get(id: string): Promise<ApiResponse<CodeqlPackage>> {
    return fetchApi(`/codeql/packages/${id}`);
  },

  // Add custom package
  async add(data: {
    name: string;
    language: ProgrammingLanguage;
    path: string;
    description?: string;
  }): Promise<ApiResponse<CodeqlPackage>> {
    return fetchApi('/codeql/packages', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Update package
  async update(
    id: string,
    data: Partial<CodeqlPackage>
  ): Promise<ApiResponse<CodeqlPackage>> {
    return fetchApi(`/codeql/packages/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  // Delete package
  async delete(id: string): Promise<ApiResponse<void>> {
    return fetchApi(`/codeql/packages/${id}`, {
      method: 'DELETE',
    });
  },

  // Toggle package enabled status
  async toggleEnabled(id: string): Promise<ApiResponse<CodeqlPackage>> {
    return fetchApi(`/codeql/packages/${id}/toggle`, {
      method: 'POST',
    });
  },

  // Get queries in package
  async getQueries(packageId: string): Promise<ApiResponse<CodeqlQuery[]>> {
    return fetchApi(`/codeql/packages/${packageId}/queries`);
  },
};

// ==================== CodeQL Generator API ====================

export const codeqlGeneratorApi = {
  // Generate CodeQL query using LLM
  async generate(data: {
    language: ProgrammingLanguage;
    vulnerabilityType?: string;
    customDescription?: string;
    includeExamples?: boolean;
    strictMode?: boolean;
  }): Promise<ApiResponse<{ generatedCode: string }>> {
    return fetchApi('/codeql/generate', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Get generation history
  async getHistory(params?: {
    page?: number;
    pageSize?: number;
  }): Promise<ApiResponse<PaginatedResponse<GeneratedCodeqlRequest>>> {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.pageSize) searchParams.set('pageSize', String(params.pageSize));

    const query = searchParams.toString();
    return fetchApi(`/codeql/generate/history${query ? `?${query}` : ''}`);
  },

  // Get generation request
  async getRequest(id: string): Promise<ApiResponse<GeneratedCodeqlRequest>> {
    return fetchApi(`/codeql/generate/${id}`);
  },

  // Save generated query
  async saveQuery(data: {
    requestId: string;
    packageId?: string;
    name: string;
  }): Promise<ApiResponse<{ success: boolean }>> {
    return fetchApi('/codeql/generate/save', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Delete generation request
  async deleteRequest(id: string): Promise<ApiResponse<void>> {
    return fetchApi(`/codeql/generate/${id}`, {
      method: 'DELETE',
    });
  },
};

// ==================== System API ====================

export const systemApi = {
  // Check system health
  async health(): Promise<ApiResponse<{
    status: string;
    codeql: boolean;
    llm: boolean;
    database: boolean;
  }>> {
    return fetchApi('/health');
  },

  // Get available languages
  async getLanguages(): Promise<ApiResponse<{ code: string; name: string }[]>> {
    return fetchApi('/languages');
  },

  // Get available query sets
  async getQuerySets(language: string): Promise<ApiResponse<{
    id: string;
    name: string;
    description: string;
  }[]>> {
    return fetchApi(`/query-sets?language=${language}`);
  },

  // Browse file system
  async browsePath(path?: string): Promise<ApiResponse<{
    path: string;
    directories: string[];
    files: string[];
  }>> {
    const params = path ? `?path=${encodeURIComponent(path)}` : '';
    return fetchApi(`/browse${params}`);
  },
};

export default {
  projects: projectsApi,
  vulnerabilities: vulnerabilitiesApi,
  reports: reportsApi,
  settings: settingsApi,
  dashboard: dashboardApi,
  codeqlPackages: codeqlPackagesApi,
  codeqlGenerator: codeqlGeneratorApi,
  system: systemApi,
};
