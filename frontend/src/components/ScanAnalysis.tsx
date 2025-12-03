import { useState, useEffect } from 'react';
import Link from 'next/link';
import { apiClient } from '@/lib/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

interface ScanAnalysisProps {
  scanId: string;
}

export function ScanAnalysis({ scanId }: ScanAnalysisProps) {
  const [analysis, setAnalysis] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAnalysis = async () => {
      // Check if analysis data is already cached
      const cacheKey = `analysis_${scanId}`;
      const cachedData = localStorage.getItem(cacheKey);
      
      if (cachedData) {
        setAnalysis(JSON.parse(cachedData));
        setLoading(false);
        return;
      }

      // Fetch from API if not cached
      try {
        const data = await apiClient.getScanAnalysis(scanId);
        setAnalysis(data);
        // Cache the data
        localStorage.setItem(cacheKey, JSON.stringify(data));
      } catch (error) {
        console.error('Failed to fetch analysis:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchAnalysis();
  }, [scanId]);

  if (loading) return <div>Loading analysis...</div>;
  if (!analysis) return <div>No analysis available</div>;

  const getMatchingPackages = (scanner: string) => {
    const exact = analysis.common_packages.exact?.filter((pkg: any) => 
      pkg.found_in.includes(scanner)
    ) || [];
    const fuzzy = analysis.common_packages.fuzzy?.filter((pkg: any) => 
      pkg.found_in.includes(scanner)
    ) || [];
    return { exact, fuzzy };
  };

  const getUniquePackages = (scanner: string) => {
    return analysis.unique_packages[scanner] || [];
  };

  return (
    <div className="space-y-8">
      {/* Common Packages Overview */}
      <Card>
        <CardHeader>
          <CardTitle>Package Comparison Overview</CardTitle>
          <CardDescription>
            Total packages found by each scanner
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            {Object.entries(analysis.total_counts).map(([scanner, count]: [string, any]) => (
              <div key={scanner} className="text-center p-4 border rounded">
                <h3 className="font-semibold capitalize">{scanner}</h3>
                <p className="text-2xl font-bold">{count}</p>
                <p className="text-sm text-gray-500">total packages</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Scanner Sections */}
      {['trivy', 'syft', 'cdxgen'].map((scanner) => {
        const matching = getMatchingPackages(scanner);
        const unique = getUniquePackages(scanner);
        
        return (
          <Card key={scanner}>
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <CardTitle className="capitalize">{scanner} Analysis</CardTitle>
                  <CardDescription>
                    Matching and unique packages found by {scanner}
                  </CardDescription>
                </div>
                <Link href={`/graph/${scanId}/${scanner}`}>
                  <Button variant="outline" size="sm">
                    View Graph
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Matching Packages */}
                <div>
                  <h4 className="font-semibold mb-3">Matching Packages</h4>
                  <div className="space-y-2">
                    {matching.exact.length === 0 && matching.fuzzy.length === 0 ? (
                      <p className="text-gray-500 text-sm">No matching packages</p>
                    ) : (
                      <>
                        {matching.exact.map((pkg: any, idx: number) => (
                          <div key={`exact-${idx}`} className="p-3 bg-green-50 border border-green-200 rounded">
                            <p className="font-medium text-sm">{pkg.name} {pkg.version}</p>
                            {pkg.purl && <p className="text-xs text-gray-600 mt-1">PURL: {pkg.purl}</p>}
                            {pkg.cpe && <p className="text-xs text-gray-600">CPE: {pkg.cpe}</p>}
                            <div className="flex gap-1 mt-2">
                              <Badge variant="outline" className="text-xs">Exact Match</Badge>
                              {pkg.found_in.map((s: string, badgeIndex: number) => (
                                <Badge key={`${s}-${badgeIndex}`} variant="secondary" className="text-xs">{s}</Badge>
                              ))}
                            </div>
                            <div className="grid grid-cols-4 gap-1 mt-2 text-xs">
                              <div>Name: 100%</div>
                              <div>Version: 100%</div>
                              <div>PURL: 100%</div>
                              <div>CPE: 100%</div>
                            </div>
                          </div>
                        ))}
                        {matching.fuzzy.map((pkg: any, idx: number) => (
                          <div key={`fuzzy-${idx}`} className="p-3 bg-yellow-50 border border-yellow-200 rounded">
                            <p className="font-medium text-sm">{pkg.name} {pkg.version}</p>
                            {pkg.purl && <p className="text-xs text-gray-600 mt-1">PURL: {pkg.purl}</p>}
                            {pkg.cpe && <p className="text-xs text-gray-600">CPE: {pkg.cpe}</p>}
                            <div className="mt-2 p-2 bg-white/50 rounded border">
                              <p className="text-xs font-medium mb-1">Similar to:</p>
                              <p className="text-xs">{pkg.similar_to.name} {pkg.similar_to.version}</p>
                              {pkg.similar_to.purl && <p className="text-xs text-gray-600">PURL: {pkg.similar_to.purl}</p>}
                              {pkg.similar_to.cpe && <p className="text-xs text-gray-600">CPE: {pkg.similar_to.cpe}</p>}
                            </div>
                            <div className="flex gap-1 mt-2">
                              <Badge variant="outline" className="text-xs">{pkg.match_type}</Badge>
                              {pkg.found_in.map((s: string, badgeIndex: number) => (
                                <Badge key={`${s}-${badgeIndex}`} variant="secondary" className="text-xs">{s}</Badge>
                              ))}
                            </div>
                            {pkg.match_scores && (
                              <div className="grid grid-cols-4 gap-1 mt-2 text-xs">
                                <div>Name: {Math.round(pkg.match_scores.name * 100)}%</div>
                                <div>Version: {Math.round(pkg.match_scores.version * 100)}%</div>
                                <div>PURL: {Math.round(pkg.match_scores.purl * 100)}%</div>
                                <div>CPE: {Math.round(pkg.match_scores.cpe * 100)}%</div>
                              </div>
                            )}
                          </div>
                        ))}
                      </>
                    )}
                  </div>
                </div>

                {/* Unique Packages */}
                <div>
                  <h4 className="font-semibold mb-3">Unique Packages ({unique.length})</h4>
                  <div className="space-y-1 max-h-96 overflow-y-auto">
                    {unique.length === 0 ? (
                      <p className="text-gray-500 text-sm">No unique packages</p>
                    ) : (
                      unique.map((pkg: any, idx: number) => (
                        <div key={idx} className="p-2 bg-blue-50 border border-blue-200 rounded">
                          <p className="text-sm font-medium">{pkg.name} {pkg.version}</p>
                          {pkg.purl && <p className="text-xs text-gray-600 mt-1">PURL: {pkg.purl}</p>}
                          {pkg.cpe && <p className="text-xs text-gray-600">CPE: {pkg.cpe}</p>}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}

      {/* Tech Stack */}
      <Card>
        <CardHeader>
          <CardTitle>Detected Tech Stack</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {analysis.tech_stack.map((tech: string, index: number) => (
              <Badge key={`${tech}-${index}`} variant="secondary">{tech}</Badge>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}