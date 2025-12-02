import { ScanResults } from '@/types/scan';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Download } from 'lucide-react';

interface ScanResultsDisplayProps {
  results: ScanResults;
}

export function ScanResultsDisplay({ results }: ScanResultsDisplayProps) {
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'failed': return 'bg-red-100 text-red-800';
      case 'in-progress': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const downloadSBOM = (scanner: string) => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
    const url = `${apiUrl}/scan/download-sbom/${results.scan_id}/${scanner}`;
    window.open(url, '_blank');
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Scan Results</CardTitle>
          <CardDescription>
            Repository: {results.repo_url}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <p className="text-sm font-medium text-gray-500">Status</p>
              <Badge className={getStatusColor(results.status)}>
                {results.status}
              </Badge>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500">Created</p>
              <p className="text-sm">{formatDate(results.created_at)}</p>
            </div>
            {results.completed_at && (
              <div>
                <p className="text-sm font-medium text-gray-500">Completed</p>
                <p className="text-sm">{formatDate(results.completed_at)}</p>
              </div>
            )}
            <div>
              <p className="text-sm font-medium text-gray-500">Tech Stack</p>
              <div className="flex flex-wrap gap-1">
                {results.tech_stack.map((tech) => (
                  <Badge key={tech} variant="outline">
                    {tech}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {results.trivy_sbom && (
          <Card>
            <CardHeader>
              <CardTitle>Trivy SBOM</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{results.trivy_sbom.component_count}</p>
              <p className="text-sm text-gray-500">Components found</p>
              {results.trivy_sbom.error && (
                <p className="text-red-500 text-sm mt-2">{results.trivy_sbom.error}</p>
              )}
              <Button 
                onClick={() => downloadSBOM('trivy')} 
                className="mt-4 w-full"
                disabled={!results.trivy_sbom.sbom}
              >
                <Download className="w-4 h-4 mr-2" />
                Download SBOM
              </Button>
            </CardContent>
          </Card>
        )}

        {results.syft_sbom && (
          <Card>
            <CardHeader>
              <CardTitle>Syft SBOM</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{results.syft_sbom.component_count}</p>
              <p className="text-sm text-gray-500">Components found</p>
              {results.syft_sbom.error && (
                <p className="text-red-500 text-sm mt-2">{results.syft_sbom.error}</p>
              )}
              <Button 
                onClick={() => downloadSBOM('syft')} 
                className="mt-4 w-full"
                disabled={!results.syft_sbom.sbom}
              >
                <Download className="w-4 h-4 mr-2" />
                Download SBOM
              </Button>
            </CardContent>
          </Card>
        )}

        {results.cdxgen_sbom && (
          <Card>
            <CardHeader>
              <CardTitle>CDXGen SBOM</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{results.cdxgen_sbom.component_count}</p>
              <p className="text-sm text-gray-500">Components found</p>
              {results.cdxgen_sbom.error && (
                <p className="text-red-500 text-sm mt-2">{results.cdxgen_sbom.error}</p>
              )}
              <Button 
                onClick={() => downloadSBOM('cdxgen')} 
                className="mt-4 w-full"
                disabled={!results.cdxgen_sbom.sbom}
              >
                <Download className="w-4 h-4 mr-2" />
                Download SBOM
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}