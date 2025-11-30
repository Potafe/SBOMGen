'use client';

import { useState, useEffect } from 'react';
import { UploadForm } from '@/components/UploadForm';
import { ScanResponse, ScanResults } from '@/types/scan';
import { apiClient } from '@/lib/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScanResultsDisplay } from '@/components/ScanResultsDisplay';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function Home() {
  const [scanResponse, setScanResponse] = useState<ScanResponse | null>(null);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // Load persisted data on mount
  useEffect(() => {
    const savedScanResponse = localStorage.getItem('scanResponse');
    const savedScanResults = localStorage.getItem('scanResults');
    
    if (savedScanResponse) {
      setScanResponse(JSON.parse(savedScanResponse));
    }
    if (savedScanResults) {
      setScanResults(JSON.parse(savedScanResults));
    }
  }, []);

  // Save to localStorage whenever data changes
  useEffect(() => {
    if (scanResponse) {
      localStorage.setItem('scanResponse', JSON.stringify(scanResponse));
    }
  }, [scanResponse]);

  useEffect(() => {
    if (scanResults) {
      localStorage.setItem('scanResults', JSON.stringify(scanResults));
    }
  }, [scanResults]);

  const handleUploadSuccess = (response: ScanResponse) => {
    setScanResponse(response);
    setScanResults(null); // Clear previous results
    setIsPolling(true);
  };

  const handleNewUpload = () => {
    setScanResponse(null);
    setScanResults(null);
    setIsPolling(false);
    localStorage.removeItem('scanResponse');
    localStorage.removeItem('scanResults');
    // Clear any cached analysis data
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('analysis_')) {
        localStorage.removeItem(key);
      }
    });
  };

  useEffect(() => {
    if (!scanResponse || !isPolling) return;

    const pollStatus = async () => {
      try {
        const statusResponse = await apiClient.getScanStatus(scanResponse.scan_id);
        if (statusResponse.status === 'completed') {
          const results = await apiClient.getScanResults(scanResponse.scan_id);
          setScanResults(results);
          setIsPolling(false);
        } else if (statusResponse.status === 'failed') {
          setIsPolling(false);
          // Handle failed status
        }
      } catch (error) {
        console.error('Error polling status:', error);
        setIsPolling(false);
      }
    };

    const interval = setInterval(pollStatus, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, [scanResponse, isPolling]);

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">SBOM Generator</h1>
          <p className="mt-2 text-gray-600">
            Upload a GitHub repository to generate Software Bill of Materials
          </p>
        </div>

        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Upload Repository</CardTitle>
            <CardDescription>
              Enter the URL of a GitHub repository to start scanning
            </CardDescription>
          </CardHeader>
          <CardContent>
            <UploadForm onUploadSuccess={handleUploadSuccess} disabled={isPolling || !!scanResponse} />
            {scanResponse && (
              <Button onClick={handleNewUpload} variant="outline" className="mt-4 w-full">
                Upload New Repository
              </Button>
            )}
          </CardContent>
        </Card>

        {scanResponse && (
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Scan Status</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-green-600">{scanResponse.message}</p>
              <p className="text-sm text-gray-500 mt-2">
                Scan ID: {scanResponse.scan_id}
              </p>
              <p className="text-sm text-gray-500">
                Status: {isPolling ? 'In Progress...' : scanResponse.status}
              </p>
            </CardContent>
          </Card>
        )}

        {scanResults && (
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Analysis</CardTitle>
                <CardDescription>
                  Compare packages across scanners to determine accuracy
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Link href={`/analysis/${scanResults.scan_id}`}>
                  <Button className="w-full">
                    View Detailed Analysis
                  </Button>
                </Link>
              </CardContent>
            </Card>
            
            <ScanResultsDisplay results={scanResults} />
          </div>
        )}
      </div>
    </div>
  );
}