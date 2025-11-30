export interface RepositoryUpload {
  repo_url: string;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface SBOMResult {
  scanner: 'trivy' | 'syft' | 'cdxgen';
  sbom: Record<string, any> | null;
  component_count: number;
  error: string | null;
  rerun: boolean;
}

export interface ScanResults {
  scan_id: string;
  status: 'pending' | 'in-progress' | 'completed' | 'failed';
  repo_url: string;
  created_at: string;
  completed_at: string | null;
  trivy_sbom: SBOMResult | null;
  syft_sbom: SBOMResult | null;
  cdxgen_sbom: SBOMResult | null;
  tech_stack: string[];
}

export interface RerunRequest {
  scan_id: string;
  scanner: 'trivy' | 'syft' | 'cdxgen';
  commands?: string[];
}