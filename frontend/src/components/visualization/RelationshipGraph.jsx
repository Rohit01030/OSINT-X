import { useState } from "react";

export default function RelationshipGraph({ data }) {
  const [selectedNode, setSelectedNode] = useState(null);

  if (!data || !data.nodes || data.nodes.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
        No graph nodes available for this investigation.
      </div>
    );
  }

  // Position nodes in a radial circular network topology layout for dynamic visual rendering
  const width = 600;
  const height = 400;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = 150;

  const positionedNodes = data.nodes.map((node, index) => {
    if (node.type === "investigation") {
      return { ...node, x: centerX, y: centerY };
    }
    const angle = (index / (data.nodes.length - 1)) * 2 * Math.PI;
    const x = centerX + radius * Math.cos(angle);
    const y = centerY + radius * Math.sin(angle);
    return { ...node, x, y };
  });

  const nodeMap = {};
  positionedNodes.forEach((n) => {
    nodeMap[n.id] = n;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono text-ink-muted">
          Nodes: <strong className="text-ink">{data.total_nodes}</strong> | Links: <strong className="text-ink">{data.total_links}</strong>
        </div>
        <div className="flex gap-3 text-[11px] font-mono">
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> Case</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" /> Module Finding</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> IOC Indicator</span>
        </div>
      </div>

      <div className="bg-base-bg border border-base-border rounded-lg p-4 flex flex-col md:flex-row gap-4 items-center justify-center">
        <svg width={width} height={height} className="max-w-full h-auto bg-base-surface/50 rounded border border-base-border/50">
          {/* Render Edge Links */}
          {data.links.map((link, idx) => {
            const source = nodeMap[link.source];
            const target = nodeMap[link.target];
            if (!source || !target) return null;
            return (
              <line
                key={idx}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke="#374151"
                strokeWidth="1.5"
                strokeDasharray={link.relation === "associated_ioc" ? "4" : "0"}
              />
            );
          })}

          {/* Render Nodes */}
          {positionedNodes.map((node) => (
            <g
              key={node.id}
              className="cursor-pointer transition-transform hover:scale-110"
              onClick={() => setSelectedNode(node)}
            >
              <circle
                cx={node.x}
                cy={node.y}
                r={node.type === "investigation" ? 22 : 14}
                fill={node.color}
                stroke="#1F2937"
                strokeWidth="2"
              />
              <text
                x={node.x}
                y={node.y + (node.type === "investigation" ? 34 : 26)}
                textAnchor="middle"
                fill="#9CA3AF"
                fontSize="10"
                fontFamily="monospace"
              >
                {node.label.length > 18 ? node.label.slice(0, 18) + "..." : node.label}
              </text>
            </g>
          ))}
        </svg>

        {/* Interactive Node Details Panel */}
        <div className="w-full md:w-64 p-4 bg-base-surface border border-base-border rounded text-xs font-mono">
          <h4 className="font-bold text-ink mb-2 border-b border-base-border pb-1">Node Inspector</h4>
          {selectedNode ? (
            <div className="space-y-2">
              <div><span className="text-ink-muted">Label:</span> <strong className="text-ink block">{selectedNode.label}</strong></div>
              <div><span className="text-ink-muted">Type:</span> <span className="text-signal">{selectedNode.type}</span></div>
              {selectedNode.module && <div><span className="text-ink-muted">Module:</span> {selectedNode.module}</div>}
              {selectedNode.ioc_type && <div><span className="text-ink-muted">IOC Type:</span> {selectedNode.ioc_type}</div>}
              {selectedNode.reputation !== undefined && <div><span className="text-ink-muted">Reputation Score:</span> {selectedNode.reputation}</div>}
            </div>
          ) : (
            <p className="text-ink-muted">Click any node on the graph to inspect node attributes.</p>
          )}
        </div>
      </div>
    </div>
  );
}
