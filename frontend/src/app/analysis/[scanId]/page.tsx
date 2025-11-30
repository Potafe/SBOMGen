'use client';

import { useParams } from 'next/navigation';
import { ScanAnalysis } from '@/components/ScanAnalysis';
import { Button } from '@/components/ui/button';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';

export default function AnalysisPage() {
  const params = useParams();
  const scanId = params.scanId as string;

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <Link href="/">
            <Button variant="outline" className="mb-4">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Home
            </Button>
          </Link>
          <h1 className="text-3xl font-bold text-gray-900">SBOM Analysis</h1>
          <p className="mt-2 text-gray-600">
            Detailed comparison of packages found by each scanner
          </p>
        </div>

        <ScanAnalysis scanId={scanId} />
      </div>
    </div>
  );
}