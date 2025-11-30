'use client';

import React, { useEffect, useState } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import Cytoscape from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import { apiClient } from '@/lib/api';

Cytoscape.use(coseBilkent);

interface SBOMGraphProps {
  scanId: string;
  scanner: string;
}

interface GraphData {
  nodes: Array<{
    id: string;
    label: string;
    properties: Record<string, any>;
  }>;
  edges: Array<{
    source: string;
    target: string;
    type: string;
  }>;
  metadata: Record<string, any>;
}

const SBOMGraph: React.FC<SBOMGraphProps> = ({ scanId, scanner }) => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  useEffect(() => {
    const fetchGraphData = async () => {
      try {
        setLoading(true);
        const data = await apiClient.getScanGraph(scanId, scanner);
        setGraphData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    };

    fetchGraphData();
  }, [scanId, scanner]);

  const elements = React.useMemo(() => {
    if (!graphData) return [];

    const nodes = graphData.nodes.map((node) => ({
      data: {
        id: node.id,
        label: node.label,
        ...node.properties,
      },
      classes: 'package-node',
    }));

    const edges = graphData.edges.map((edge, index) => ({
      data: {
        id: `edge-${index}`,
        source: edge.source,
        target: edge.target,
        type: edge.type,
      },
      classes: 'dependency-edge',
    }));

    return [...nodes, ...edges];
  }, [graphData]);

  const layout = {
    name: 'cose-bilkent',
    animate: true,
    animationDuration: 1000,
    nodeDimensionsIncludeLabels: true,
  };

  const stylesheet = [
    {
      selector: 'node',
      style: {
        'background-color': '#4A90E2',
        'label': 'data(label)',
        'color': '#fff',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'width': 'label',
        'height': 'label',
        'padding': '8px',
        'shape': 'round-rectangle',
      },
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#ccc',
        'target-arrow-color': '#ccc',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
      },
    },
    {
      selector: '.package-node',
      style: {
        'background-color': '#4A90E2',
      },
    },
    {
      selector: '.dependency-edge',
      style: {
        'line-color': '#666',
        'target-arrow-color': '#666',
      },
    },
    {
      selector: 'node:selected',
      style: {
        'background-color': '#FF6B6B',
        'border-width': 3,
        'border-color': '#FF0000',
      },
    },
  ];

  const handleNodeClick = (event: any) => {
    const node = event.target;
    setSelectedNode(node.data());
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-lg">Loading graph...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-red-500">Error: {error}</div>
      </div>
    );
  }

  return (
    <div className="w-full h-screen flex">
      <div className="flex-1">
        <CytoscapeComponent
          elements={elements}
          layout={layout}
          stylesheet={stylesheet}
          cy={(cy) => {
            cy.on('tap', 'node', handleNodeClick);
          }}
          style={{ width: '100%', height: '100%' }}
        />
      </div>
      {selectedNode && (
        <div className="w-80 bg-gray-100 p-4 overflow-y-auto">
          <h3 className="text-lg font-bold mb-4">Package Details</h3>
          <div className="space-y-2">
            <div>
              <strong>Name:</strong> {selectedNode.name || selectedNode.label}
            </div>
            <div>
              <strong>Version:</strong> {selectedNode.version || 'N/A'}
            </div>
            <div>
              <strong>Type:</strong> {selectedNode.type || 'N/A'}
            </div>
            <div>
              <strong>PURL:</strong> {selectedNode.purl || 'N/A'}
            </div>
            {selectedNode.description && (
              <div>
                <strong>Description:</strong> {selectedNode.description}
              </div>
            )}
            {selectedNode.licenses && selectedNode.licenses.length > 0 && (
              <div>
                <strong>Licenses:</strong> {selectedNode.licenses.join(', ')}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SBOMGraph;