import axios from 'axios';
import { RepositoryUpload, ScanResponse, ScanResults, RerunRequest } from '@/types/scan';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:9000/api/v1';

export const apiClient = {
  uploadRepository: async (data: RepositoryUpload): Promise<ScanResponse> => {
    const response = await axios.post(`${API_BASE_URL}/scan/upload-repository`, data);
    return response.data;
  },
  
  getScanResults: async (scanId: string): Promise<ScanResults> => {
    const response = await axios.get(`${API_BASE_URL}/scan/sbom-results/${scanId}`);
    return response.data;
  },

  getScanStatus: async (scanId: string): Promise<{ status: string }> => {
    const response = await axios.get(`${API_BASE_URL}/scan/scan-status/${scanId}`);
    return response.data;
  },

  rerunScanner: async (data: RerunRequest): Promise<Record<string, any>> => {
    const response = await axios.post(`${API_BASE_URL}/scan/rerun-scanner`, data);
    return response.data;
  },

  getScanLogs: async (scanId: string): Promise<Record<string, any>> => {
    const response = await axios.get(`${API_BASE_URL}/scan/logs/${scanId}`);
    return response.data;
  },

  getScanAnalysis: async (scanId: string): Promise<any> => {
    const response = await axios.get(`${API_BASE_URL}/scan/scan-analysis/${scanId}`);
    return response.data;
  },

  getScanGraph: async (scanId: string, scanner: string): Promise<any> => {
    const response = await axios.get(`${API_BASE_URL}/scan/scan-graph/${scanId}/${scanner}`);
    return response.data;
  },
};