import React, { useEffect, useRef, useState } from 'react';
import type { AttackPath, AttackPathNode } from '../../types';

interface AttackPathGraphProps {
  path: AttackPath;
}

export const AttackPathGraph: React.FC<AttackPathGraphProps> = ({ path }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackPathNode | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Layout positions
    const nodePositions: Record<string, { x: number; y: number }> = {};
    const totalNodes = path.nodes.length;
    const spacing = canvas.width / (totalNodes + 1);
    const startY = canvas.height / 2;

    path.nodes.forEach((node, index) => {
      nodePositions[node.id] = {
        x: spacing * (index + 1),
        y: startY + (index % 2 === 0 ? -30 : 30),
      };
    });

    // Draw Edges
    path.edges.forEach((edge) => {
      const src = nodePositions[edge.source];
      const tgt = nodePositions[edge.target];
      if (src && tgt) {
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = edge.type === 'trust' ? '#ef4444' : '#6366f1';
        ctx.lineWidth = 2;
        ctx.setLineDash(edge.type === 'trust' ? [6, 4] : []);
        ctx.stroke();

        // Edge label
        ctx.fillStyle = '#9ca3af';
        ctx.font = '10px Inter';
        ctx.fillText(edge.label, (src.x + tgt.x) / 2 - 20, (src.y + tgt.y) / 2 - 10);
      }
    });

    // Draw Nodes
    path.nodes.forEach((node) => {
      const pos = nodePositions[node.id];
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 24, 0, 2 * Math.PI);
      ctx.fillStyle = selectedNode?.id === node.id ? '#10b981' : '#1f2937';
      ctx.fill();
      ctx.strokeStyle = node.type === 'database' || node.type === 'asset' ? '#ef4444' : '#3b82f6';
      ctx.lineWidth = 3;
      ctx.stroke();

      // Node Label
      ctx.fillStyle = '#ffffff';
      ctx.font = '11px Inter';
      ctx.textAlign = 'center';
      ctx.fillText(node.label.length > 18 ? node.label.substring(0, 16) + '...' : node.label, pos.x, pos.y + 40);
    });
  }, [path, selectedNode]);

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const spacing = canvas.width / (path.nodes.length + 1);
    const startY = canvas.height / 2;

    for (let i = 0; i < path.nodes.length; i++) {
      const node = path.nodes[i];
      const x = spacing * (i + 1);
      const y = startY + (i % 2 === 0 ? -30 : 30);
      const dist = Math.sqrt((clickX - x) ** 2 + (clickY - y) ** 2);
      if (dist <= 24) {
        setSelectedNode(node);
        return;
      }
    }
    setSelectedNode(null);
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="glass-card" style={{ position: 'relative', overflow: 'hidden' }}>
        <canvas
          ref={canvasRef}
          width={750}
          height={260}
          onClick={handleCanvasClick}
          style={{ width: '100%', height: '260px', cursor: 'pointer', display: 'block' }}
        />
        <div style={{ position: 'absolute', top: 12, right: 16, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Click nodes to inspect node properties
        </div>
      </div>

      {selectedNode && (
        <div className="glass-card" style={{ borderLeft: '4px solid var(--color-accent-indigo)' }}>
          <h4 style={{ fontSize: '0.9rem', marginBottom: '0.25rem' }}>Selected Topology Node: {selectedNode.label}</h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Node Type: <strong style={{ color: '#fff' }}>{selectedNode.type.toUpperCase()}</strong> | Risk Impact: <strong style={{ color: 'var(--color-critical)' }}>{selectedNode.risk_score}</strong>
          </p>
        </div>
      )}
    </div>
  );
};
