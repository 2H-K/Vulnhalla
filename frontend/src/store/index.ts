import { create } from 'zustand';
import type {
  Project,
  Vulnerability,
  AnalysisReport,
  SystemSettings,
  DashboardStats,
  ScanConfig,
  Severity,
  VulnerabilityStatus,
} from '../types';
import api from '../services/api';

// ==================== Projects Store ====================

interface ProjectsState {
  projects: Project[];
  currentProject: Project | null;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  fetchProjects: (params?: {
    language?: string;
    status?: string;
    search?: string;
  }) => Promise<void>;
  fetchProject: (id: string) => Promise<void>;
  createProject: (data: {
    name: string;
    language: string;
    path: string;
    scanConfig?: ScanConfig;
  }) => Promise<Project | null>;
  updateProject: (id: string, data: Partial<Project>) => Promise<boolean>;
  deleteProject: (id: string) => Promise<boolean>;
  startAnalysis: (projectId: string, config: ScanConfig) => Promise<AnalysisReport | null>;
  setCurrentProject: (project: Project | null) => void;
  clearError: () => void;
}

export const useProjectsStore = create<ProjectsState>((set) => ({
  projects: [],
  currentProject: null,
  isLoading: false,
  error: null,

  fetchProjects: async (params) => {
    set({ isLoading: true, error: null });
    const response = await api.projects.list(params);
    if (response.success && response.data) {
      set({
        projects: response.data.items,
        isLoading: false,
      });
    } else {
      set({
        error: response.error || 'Failed to fetch projects',
        isLoading: false,
      });
    }
  },

  fetchProject: async (id) => {
    set({ isLoading: true, error: null });
    const response = await api.projects.get(id);
    if (response.success && response.data) {
      set({
        currentProject: response.data,
        isLoading: false,
      });
    } else {
      set({
        error: response.error || 'Failed to fetch project',
        isLoading: false,
      });
    }
  },

  createProject: async (data) => {
    set({ isLoading: true, error: null });
    const response = await api.projects.create(data);
    if (response.success && response.data) {
      const newProject = response.data;
      set((state) => ({
        projects: [...state.projects, newProject],
        isLoading: false,
      }));
      return newProject;
    } else {
      set({
        error: response.error || 'Failed to create project',
        isLoading: false,
      });
      return null;
    }
  },

  updateProject: async (id, data) => {
    set({ isLoading: true, error: null });
    const response = await api.projects.update(id, data);
    if (response.success && response.data) {
      set((state) => ({
        projects: state.projects.map((p) =>
          p.id === id ? response.data! : p
        ),
        currentProject:
          state.currentProject?.id === id ? response.data! : state.currentProject,
        isLoading: false,
      }));
      return true;
    } else {
      set({
        error: response.error || 'Failed to update project',
        isLoading: false,
      });
      return false;
    }
  },

  deleteProject: async (id) => {
    set({ isLoading: true, error: null });
    const response = await api.projects.delete(id);
    if (response.success) {
      set((state) => ({
        projects: state.projects.filter((p) => p.id !== id),
        currentProject:
          state.currentProject?.id === id ? null : state.currentProject,
        isLoading: false,
      }));
      return true;
    } else {
      set({
        error: response.error || 'Failed to delete project',
        isLoading: false,
      });
      return false;
    }
  },

  startAnalysis: async (projectId, config) => {
    set({ isLoading: true, error: null });
    const response = await api.projects.startAnalysis(projectId, config);
    if (response.success && response.data) {
      // Update project status
      set((state) => ({
        projects: state.projects.map((p) =>
          p.id === projectId ? { ...p, status: 'analyzing' as const } : p
        ),
        isLoading: false,
      }));
      return response.data;
    } else {
      set({
        error: response.error || 'Failed to start analysis',
        isLoading: false,
      });
      return null;
    }
  },

  setCurrentProject: (project) => {
    set({ currentProject: project });
  },

  clearError: () => {
    set({ error: null });
  },
}));

// ==================== Vulnerabilities Store ====================

interface VulnerabilitiesState {
  vulnerabilities: Vulnerability[];
  currentVulnerability: Vulnerability | null;
  totalCount: number;
  page: number;
  pageSize: number;
  isLoading: boolean;
  error: string | null;
  
  // Filters
  filters: {
    projectId?: string;
    severity?: Severity;
    status?: VulnerabilityStatus;
  };
  
  // Actions
  fetchVulnerabilities: (params?: {
    projectId?: string;
    severity?: string;
    status?: string;
    page?: number;
    pageSize?: number;
  }) => Promise<void>;
  fetchVulnerability: (id: string) => Promise<void>;
  updateStatus: (id: string, status: VulnerabilityStatus, reason?: string) => Promise<boolean>;
  batchUpdateStatus: (ids: string[], status: VulnerabilityStatus) => Promise<boolean>;
  setFilters: (filters: Partial<VulnerabilitiesState['filters']>) => void;
  setCurrentVulnerability: (vulnerability: Vulnerability | null) => void;
  clearError: () => void;
}

export const useVulnerabilitiesStore = create<VulnerabilitiesState>((set) => ({
  vulnerabilities: [],
  currentVulnerability: null,
  totalCount: 0,
  page: 1,
  pageSize: 20,
  isLoading: false,
  error: null,
  filters: {},

  fetchVulnerabilities: async (params) => {
    set({ isLoading: true, error: null });
    const response = await api.vulnerabilities.list(params);
    if (response.success && response.data) {
      set({
        vulnerabilities: response.data.items,
        totalCount: response.data.total,
        page: params?.page || 1,
        pageSize: params?.pageSize || 20,
        isLoading: false,
      });
    } else {
      set({
        error: response.error || 'Failed to fetch vulnerabilities',
        isLoading: false,
      });
    }
  },

  fetchVulnerability: async (id) => {
    set({ isLoading: true, error: null });
    const response = await api.vulnerabilities.get(id);
    if (response.success && response.data) {
      set({
        currentVulnerability: response.data,
        isLoading: false,
      });
    } else {
      set({
        error: response.error || 'Failed to fetch vulnerability',
        isLoading: false,
      });
    }
  },

  updateStatus: async (id, status, reason) => {
    set({ isLoading: true, error: null });
    const response = await api.vulnerabilities.updateStatus(id, status, reason);
    if (response.success && response.data) {
      set((state) => ({
        vulnerabilities: state.vulnerabilities.map((v) =>
          v.id === id ? response.data! : v
        ),
        currentVulnerability:
          state.currentVulnerability?.id === id
            ? response.data!
            : state.currentVulnerability,
        isLoading: false,
      }));
      return true;
    } else {
      set({
        error: response.error || 'Failed to update status',
        isLoading: false,
      });
      return false;
    }
  },

  batchUpdateStatus: async (ids, status) => {
    set({ isLoading: true, error: null });
    const response = await api.vulnerabilities.batchUpdateStatus(ids, status);
    if (response.success) {
      // Refetch to get updated data
      set({ isLoading: false });
      return true;
    } else {
      set({
        error: response.error || 'Failed to batch update status',
        isLoading: false,
      });
      return false;
    }
  },

  setFilters: (filters) => {
    set((state) => ({
      filters: { ...state.filters, ...filters },
    }));
  },

  setCurrentVulnerability: (vulnerability) => {
    set({ currentVulnerability: vulnerability });
  },

  clearError: () => {
    set({ error: null });
  },
}));

// ==================== Settings Store ====================

interface SettingsState {
  settings: SystemSettings | null;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  fetchSettings: () => Promise<void>;
  updateSettings: (data: Partial<SystemSettings>) => Promise<boolean>;
  testCodeql: () => Promise<{ version: string; path: string } | null>;
  testLlm: () => Promise<boolean>;
  clearError: () => void;
}

export const useSettingsStore = create<SettingsState>((set) => ({
  settings: null,
  isLoading: false,
  error: null,

  fetchSettings: async () => {
    set({ isLoading: true, error: null });
    const response = await api.settings.get();
    if (response.success && response.data) {
      set({
        settings: response.data,
        isLoading: false,
      });
    } else {
      set({
        error: response.error || 'Failed to fetch settings',
        isLoading: false,
      });
    }
  },

  updateSettings: async (data) => {
    set({ isLoading: true, error: null });
    const response = await api.settings.update(data);
    if (response.success && response.data) {
      set({
        settings: response.data,
        isLoading: false,
      });
      return true;
    } else {
      set({
        error: response.error || 'Failed to update settings',
        isLoading: false,
      });
      return false;
    }
  },

  testCodeql: async () => {
    set({ isLoading: true, error: null });
    const response = await api.settings.testCodeql();
    if (response.success && response.data) {
      set({ isLoading: false });
      return response.data;
    } else {
      set({
        error: response.error || 'CodeQL test failed',
        isLoading: false,
      });
      return null;
    }
  },

  testLlm: async () => {
    set({ isLoading: true, error: null });
    const response = await api.settings.testLlm();
    if (response.success && response.data?.success) {
      set({ isLoading: false });
      return true;
    } else {
      set({
        error: response.error || 'LLM test failed',
        isLoading: false,
      });
      return false;
    }
  },

  clearError: () => {
    set({ error: null });
  },
}));

// ==================== Dashboard Store ====================

interface DashboardState {
  stats: DashboardStats | null;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  fetchStats: () => Promise<void>;
  clearError: () => void;
}

export const useDashboardStore = create<DashboardState>((set) => ({
  stats: null,
  isLoading: false,
  error: null,

  fetchStats: async () => {
    set({ isLoading: true, error: null });
    const response = await api.dashboard.getStats();
    if (response.success && response.data) {
      set({
        stats: response.data,
        isLoading: false,
      });
    } else {
      set({
        error: response.error || 'Failed to fetch stats',
        isLoading: false,
      });
    }
  },

  clearError: () => {
    set({ error: null });
  },
}));

// ==================== UI Store ====================

interface UIState {
  // Sidebar
  sidebarCollapsed: boolean;
  
  // Modals
  newProjectModalOpen: boolean;
  scanConfigModalOpen: boolean;
  
  // Notifications
  notifications: Array<{
    id: string;
    type: 'success' | 'error' | 'info' | 'warning';
    message: string;
  }>;
  
  // Actions
  toggleSidebar: () => void;
  setNewProjectModalOpen: (open: boolean) => void;
  setScanConfigModalOpen: (open: boolean) => void;
  addNotification: (notification: Omit<UIState['notifications'][0], 'id'>) => void;
  removeNotification: (id: string) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  newProjectModalOpen: false,
  scanConfigModalOpen: false,
  notifications: [],

  toggleSidebar: () => {
    set((state) => ({
      sidebarCollapsed: !state.sidebarCollapsed,
    }));
  },

  setNewProjectModalOpen: (open) => {
    set({ newProjectModalOpen: open });
  },

  setScanConfigModalOpen: (open) => {
    set({ scanConfigModalOpen: open });
  },

  addNotification: (notification) => {
    const id = Date.now().toString();
    set((state) => ({
      notifications: [...state.notifications, { ...notification, id }],
    }));
    // Auto remove after 5 seconds
    setTimeout(() => {
      set((state) => ({
        notifications: state.notifications.filter((n) => n.id !== id),
      }));
    }, 5000);
  },

  removeNotification: (id) => {
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    }));
  },
}));

// Export all stores
export default {
  useProjectsStore,
  useVulnerabilitiesStore,
  useSettingsStore,
  useDashboardStore,
  useUIStore,
};