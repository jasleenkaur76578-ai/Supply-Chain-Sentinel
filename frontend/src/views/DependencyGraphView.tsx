import React, { useEffect, useState, useCallback } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Node,
  Edge
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Boxes,
  ShieldAlert,
  GitFork,
  RadioTower,
  X,
  Layers,
  ArrowRight,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { Application } from '../types';

interface DependencyGraphViewProps {
  initialAppId?: string;
  onNavigate: (view: string, targetId?: string) => void;
}

export const DependencyGraphView: React.FC<DependencyGraphViewProps> = ({ initialAppId, onNavigate }) => {
  const [apps, setApps] = useState<Application[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>(initialAppId || '');
  const [depth, setDepth] = useState<number>(3);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(false);
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);

  useEffect(() => {
    loadApps();
  }, []);

  useEffect(() => {
    if (initialAppId) {
      setSelectedAppId(initialAppId);
    }
  }, [initialAppId]);

  useEffect(() => {
    if (selectedAppId) {
      loadGraph(selectedAppId, depth);
    }
  }, [selectedAppId, depth]);

  const loadApps = async () => {
    try {
      const data = await api.getApplications();
      setApps(data);
      if (!selectedAppId && data.length > 0) {
        setSelectedAppId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadGraph = async (appId: string, maxDepth: number) => {
    try {
      setLoading(true);
      const graphData = await api.getApplicationGraph(appId, maxDepth);

      // Transform raw backend graph into ReactFlow styled nodes
      const flowNodes: Node[] = (graphData.nodes || []).map((n) => {
        const isApp = n.type === 'applicationNode';
        const isService = n.type === 'serviceNode';
        const isVuln = n.type === 'vulnerabilityNode';

        let bg = '#1E293B';
        let border = '#334155';
        let text = '#F8FAFC';

        if (isApp) {
          bg = '#1E1B4B';
          border = '#6366F1';
        } else if (isService) {
          bg = '#022C22';
          border = '#10B981';
        } else if (isVuln) {
          bg = n.data.severity === 'CRITICAL' ? '#450A0A' : '#431407';
          border = n.data.severity === 'CRITICAL' ? '#EF4444' : '#F97316';
        } else if (n.data.severity === 'CRITICAL') {
          bg = '#450A0A';
          border = '#EF4444';
        } else if (n.data.severity === 'HIGH') {
          bg = '#431407';
          border = '#F97316';
        }

        return {
          id: n.id,
          position: n.position || { x: 100, y: 100 },
          data: {
            ...n.data,
            label: (
              <div className="p-2 text-left font-mono">
                <div className="text-[10px] text-slate-400 uppercase font-semibold">
                  {n.data.entity_type || (isApp ? 'APPLICATION' : isService ? 'SERVICE' : isVuln ? 'VULNERABILITY' : 'PACKAGE')}
                </div>
                <div className="font-bold text-xs truncate max-w-[180px]">{n.data.label}</div>
                {n.data.cvss && (
                  <div className="text-[10px] text-red-400 mt-0.5">CVSS: {n.data.cvss} • {n.data.severity}</div>
                )}
                {n.data.criticality && (
                  <div className="text-[10px] text-indigo-400 mt-0.5">{n.data.criticality}</div>
                )}
              </div>
            )
          },
          style: {
            background: bg,
            color: text,
            border: `1.5px solid ${border}`,
            borderRadius: '10px',
            width: 200,
            boxShadow: isVuln || n.data.severity === 'CRITICAL' ? '0 0 15px rgba(239, 68, 68, 0.25)' : 'none'
          }
        };
      });

      const flowEdges: Edge[] = (graphData.edges || []).map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.animated || false,
        style: e.style || { stroke: '#475569', strokeWidth: 1.5 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: e.style?.stroke || '#475569',
        },
      }));

      setNodes(flowNodes);
      setEdges(flowEdges);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const onNodeClick = (_: any, node: Node) => {
    // Extract raw payload data without react element label
    const rawData = { ...node.data };
    delete rawData.label;
    setSelectedNodeData({ id: node.id, ...rawData });
  };

  return (
    <div className="space-y-4 h-[calc(100vh-130px)] flex flex-col">
      {/* Graph Toolbar */}
      <div className="p-4 rounded-xl bg-[#111C30] border border-slate-800 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <label className="text-xs font-mono text-slate-400">Target Application:</label>
          <select
            value={selectedAppId}
            onChange={(e) => setSelectedAppId(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
          >
            {apps.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name} ({app.environment})
              </option>
            ))}
          </select>
        </div>

        {/* Depth Filter Slider */}
        <div className="flex items-center gap-3 font-mono text-xs">
          <span className="text-slate-400">Dependency Depth:</span>
          <input
            type="range"
            min="1"
            max="5"
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            className="w-28 accent-sky-400 cursor-pointer"
          />
          <span className="text-sky-400 font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
            {depth} {depth === 1 ? 'Direct' : 'Levels'}
          </span>
        </div>

        {/* Legend */}
        <div className="hidden xl:flex items-center gap-3 text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#1E1B4B] border border-[#6366F1]" />
            <span>Application</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#022C22] border border-[#10B981]" />
            <span>Business Service</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#1E293B] border border-[#334155]" />
            <span>Package</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#450A0A] border border-[#EF4444]" />
            <span>Vulnerable / Critical</span>
          </div>
        </div>
      </div>

      {/* Main Canvas & Context Drawer */}
      <div className="flex-1 rounded-xl bg-[#0F172A] border border-slate-800 relative overflow-hidden flex">
        <div className="flex-1 h-full w-full relative">
          {loading && (
            <div className="absolute inset-0 z-20 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center">
              <span className="text-xs font-mono text-sky-400 animate-pulse">Computing Graph Topology...</span>
            </div>
          )}
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            fitView
            minZoom={0.2}
            maxZoom={1.5}
          >
            <Background color="#1E293B" gap={20} size={1.5} />
            <Controls className="bg-slate-900 border-slate-700 text-white fill-white" />
            <MiniMap
              nodeColor={(n) => (n.style?.background as string) || '#1E293B'}
              className="bg-slate-900 border border-slate-800 rounded-lg"
            />
          </ReactFlow>
        </div>

        {/* Contextual Node Detail Drawer */}
        {selectedNodeData && (
          <div className="w-80 bg-[#111C30] border-l border-slate-800 p-5 flex flex-col justify-between z-20 shadow-2xl animate-fade-in font-mono text-xs overflow-y-auto">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="text-[10px] uppercase font-bold text-sky-400 tracking-wider">
                  Entity Intelligence Card
                </span>
                <button
                  onClick={() => setSelectedNodeData(null)}
                  className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div>
                <h4 className="text-sm font-bold text-white break-all">
                  {selectedNodeData.name || selectedNodeData.id}
                </h4>
                {selectedNodeData.version && (
                  <p className="text-slate-400 text-xs mt-0.5">Version: {selectedNodeData.version}</p>
                )}
                {selectedNodeData.ecosystem && (
                  <p className="text-slate-500 text-[11px]">Ecosystem: {selectedNodeData.ecosystem}</p>
                )}
              </div>

              {/* Entity Specific Attributes */}
              {selectedNodeData.severity && (
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[10px]">RISK SEVERITY</span>
                    <Badge variant={selectedNodeData.severity}>{selectedNodeData.severity}</Badge>
                  </div>
                  {selectedNodeData.cvss && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-[10px]">CVSS SCORE</span>
                      <span className="font-bold text-red-400">{selectedNodeData.cvss}/10</span>
                    </div>
                  )}
                  {selectedNodeData.is_kev && (
                    <Badge variant="KEV">CISA KEV ACTIVE</Badge>
                  )}
                </div>
              )}

              {selectedNodeData.criticality && (
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[10px]">BUSINESS CRITICALITY</span>
                  <div className="font-bold text-indigo-400">{selectedNodeData.criticality}</div>
                  {selectedNodeData.financial_impact && (
                    <div className="text-[11px] text-slate-300">
                      Disruption Cost: ${Number(selectedNodeData.financial_impact).toLocaleString()}/hr
                    </div>
                  )}
                </div>
              )}

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-400 text-[11px] leading-relaxed">
                Graph linkage verifies this component's presence in the application's compiled dependency tree.
              </div>
            </div>

            {/* Quick Actions */}
            <div className="pt-4 border-t border-slate-800 space-y-2">
              <button
                onClick={() => onNavigate('propagation', selectedNodeData.name || selectedNodeData.id)}
                className="w-full py-2 bg-sky-500/15 hover:bg-sky-500/25 text-sky-400 border border-sky-500/30 rounded-lg font-bold flex items-center justify-center gap-1.5 transition-colors"
              >
                <RadioTower className="w-3.5 h-3.5" />
                <span>Simulate Blast Radius</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
