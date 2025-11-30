'use client';

import { useParams } from 'next/navigation';
import SBOMGraph from '@/components/SBOMGraph';

export default function GraphPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const scanner = params.scanner as string;

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-4">
            <h1 className="text-2xl font-bold text-gray-900">
              SBOM Graph - {scanner.toUpperCase()}
            </h1>
            <p className="text-sm text-gray-600 mt-1">
              Scan ID: {scanId}
            </p>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-4 border-b">
            <h2 className="text-lg font-semibold">Package Dependencies</h2>
            <p className="text-sm text-gray-600">
              Click on packages to view their details. Use mouse wheel to zoom, drag to pan.
            </p>
          </div>
          <div className="h-[calc(100vh-200px)]">
            <SBOMGraph scanId={scanId} scanner={scanner} />
          </div>
        </div>
      </div>
    </div>
  );
}