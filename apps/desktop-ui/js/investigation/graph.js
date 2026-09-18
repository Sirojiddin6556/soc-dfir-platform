import { filterGraphByLayer } from './layers.js';

export class InvestigationGraph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas ? canvas.getContext('2d') : null;
    this.minimapCanvas = document.getElementById('minimapCanvas');
    this.minimapCtx = this.minimapCanvas ? this.minimapCanvas.getContext('2d') : null;
    this.tooltipEl = document.getElementById('graphTooltip');

    this.rawGraph = { nodes: [], edges: [] };
    this.activeLayer = 'attack';
    this.filteredGraph = { nodes: [], edges: [] };

    this.zoom = 1.0;
    this.panX = 0;
    this.panY = 0;
    this.isDragging = false;
    this.dragStart = { x: 0, y: 0 };
    this.selectedNode = null;
    this.hoveredNode = null;
    this.onSelect = null;

    this.nodePositions = new Map();
    this.animTime = 0;
    this.animFrameId = null;

    this.initEvents();
    this.startAnimationLoop();
  }

  initEvents() {
    if (!this.canvas) return;

    window.addEventListener('resize', () => this.resizeCanvas());
    this.resizeCanvas();

    this.canvas.addEventListener('mousedown', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const x = (e.clientX - rect.left - this.panX) / this.zoom;
      const y = (e.clientY - rect.top - this.panY) / this.zoom;

      const hit = this.hitTest(x, y);
      if (hit) {
        this.selectedNode = hit;
        if (this.onSelect) this.onSelect(hit);
        this.draw();
      } else {
        this.isDragging = true;
        this.dragStart = { x: e.clientX - this.panX, y: e.clientY - this.panY };
      }
    });

    window.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        this.panX = e.clientX - this.dragStart.x;
        this.panY = e.clientY - this.dragStart.y;
        this.draw();
      } else if (this.canvas) {
        const rect = this.canvas.getBoundingClientRect();
        const x = (e.clientX - rect.left - this.panX) / this.zoom;
        const y = (e.clientY - rect.top - this.panY) / this.zoom;
        const hit = this.hitTest(x, y);

        if (hit !== this.hoveredNode) {
          this.hoveredNode = hit;
          this.canvas.style.cursor = hit ? 'pointer' : 'default';
          this.updateTooltip(hit, e.clientX, e.clientY);
        } else if (hit) {
          this.updateTooltipPos(e.clientX, e.clientY);
        }
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      const zoomFactor = e.deltaY < 0 ? 1.12 : 0.88;
      const newZoom = Math.max(0.3, Math.min(3.5, this.zoom * zoomFactor));

      this.panX = mouseX - (mouseX - this.panX) * (newZoom / this.zoom);
      this.panY = mouseY - (mouseY - this.panY) * (newZoom / this.zoom);
      this.zoom = newZoom;

      const label = document.getElementById('zoomLabel');
      if (label) label.textContent = `${Math.round(this.zoom * 100)}%`;
      this.draw();
    });
  }

  startAnimationLoop() {
    const loop = (ts) => {
      this.animTime = ts;
      // Continuously animate attack pulses and particle flows
      if (this.filteredGraph.nodes.some(n => n.in_attack_path)) {
        this.draw();
      }
      this.animFrameId = requestAnimationFrame(loop);
    };
    this.animFrameId = requestAnimationFrame(loop);
  }

  resizeCanvas() {
    if (!this.canvas) return;
    const parent = this.canvas.parentElement;
    if (!parent) return;

    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = parent.clientWidth * dpr;
    this.canvas.height = parent.clientHeight * dpr;
    if (this.ctx) {
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    this.draw();
  }

  setZoom(val) {
    this.zoom = Math.max(0.3, Math.min(3.5, val));
    const label = document.getElementById('zoomLabel');
    if (label) label.textContent = `${Math.round(this.zoom * 100)}%`;
    this.draw();
  }

  resetView() {
    this.zoom = 1.0;
    const parent = this.canvas ? this.canvas.parentElement : null;
    this.panX = parent ? parent.clientWidth / 2 - 200 : 200;
    this.panY = parent ? parent.clientHeight / 2 - 150 : 150;
    const label = document.getElementById('zoomLabel');
    if (label) label.textContent = '100%';
    this.draw();
  }

  render(graph, layer = 'attack') {
    this.rawGraph = graph || { nodes: [], edges: [] };
    this.activeLayer = layer;
    this.filteredGraph = filterGraphByLayer(this.rawGraph, layer);

    const emptyEl = document.getElementById('graphEmptyState');
    if (emptyEl) {
      emptyEl.style.display = this.filteredGraph.nodes.length === 0 ? 'flex' : 'none';
    }

    this.layoutNodes();
    this.draw();
  }

  layoutNodes() {
    const nodes = this.filteredGraph.nodes;
    if (nodes.length === 0) return;

    const parent = this.canvas ? this.canvas.parentElement : null;
    const width = parent ? parent.clientWidth : 800;
    const height = parent ? parent.clientHeight : 500;
    const centerX = width / 2;
    const centerY = height / 2;

    this.nodePositions.clear();

    const hostNodes = nodes.filter(n => n.type === 'host');
    const procNodes = nodes.filter(n => n.type === 'process');
    const netNodes = nodes.filter(n => n.type === 'network');
    const findNodes = nodes.filter(n => n.type === 'finding');

    hostNodes.forEach((n, i) => {
      this.nodePositions.set(n.id, { x: centerX - 240 + i * 220, y: centerY - 140 });
    });

    const attackProcs = procNodes.filter(p => p.in_attack_path);
    const normalProcs = procNodes.filter(p => !p.in_attack_path);

    attackProcs.forEach((n, i) => {
      this.nodePositions.set(n.id, { x: centerX - 20 + i * 140, y: centerY + 20 + (i % 2) * 50 });
    });

    normalProcs.forEach((n, i) => {
      const angle = (i / Math.max(1, normalProcs.length)) * Math.PI * 2;
      const radius = 180 + (i % 3) * 45;
      this.nodePositions.set(n.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      });
    });

    netNodes.forEach((n, i) => {
      const angle = (i / Math.max(1, netNodes.length)) * Math.PI * 1.6;
      this.nodePositions.set(n.id, {
        x: centerX + 280 + Math.cos(angle) * 110,
        y: centerY - 40 + Math.sin(angle) * 130
      });
    });

    findNodes.forEach((n, i) => {
      this.nodePositions.set(n.id, {
        x: centerX - 320 + (i % 2) * 40,
        y: centerY + 60 + i * 55
      });
    });
  }

  hitTest(x, y) {
    for (const node of this.filteredGraph.nodes) {
      const pos = this.nodePositions.get(node.id);
      if (!pos) continue;
      const r = node.type === 'host' ? 28 : (node.type === 'finding' ? 24 : 20);
      const dist = Math.hypot(pos.x - x, pos.y - y);
      if (dist <= r) return node;
    }
    return null;
  }

  updateTooltip(node, clientX, clientY) {
    if (!this.tooltipEl) return;
    if (!node) {
      this.tooltipEl.style.display = 'none';
      return;
    }

    const icon = node.type === 'host' ? '💻' : (node.type === 'process' ? '⚙️' : (node.type === 'finding' ? '⚠️' : '⛓️'));
    const statusColor = node.in_attack_path ? 'var(--accent-critical)' : 'var(--accent-info)';

    this.tooltipEl.innerHTML = `
      <div class="graph-tooltip-title">
        <span>${icon}</span>
        <span>${node.label || node.id}</span>
        <span class="badge ${node.in_attack_path ? 'badge-critical' : 'badge-net'}" style="margin-left: auto; font-size: 8px;">${node.type.toUpperCase()}</span>
      </div>
      <div class="graph-tooltip-detail">
        <div>ID: <strong style="color: #f8fafc;">${node.id}</strong></div>
        ${node.subtitle ? `<div>Инфо: ${node.subtitle}</div>` : ''}
        ${node.path ? `<div>Путь: ${node.path}</div>` : ''}
        <div style="margin-top: 4px; color: ${statusColor}; font-weight: 600;">
          ${node.in_attack_path ? '⚠ Угроза зафиксирована в цепи атаки' : '✓ Статус верифицирован (Normal)'}
        </div>
      </div>
    `;

    this.tooltipEl.style.display = 'block';
    this.updateTooltipPos(clientX, clientY);
  }

  updateTooltipPos(clientX, clientY) {
    if (!this.tooltipEl) return;
    this.tooltipEl.style.left = `${clientX + 16}px`;
    this.tooltipEl.style.top = `${clientY + 12}px`;
  }

  draw() {
    if (!this.ctx || !this.canvas) return;
    const ctx = this.ctx;
    const parent = this.canvas.parentElement;
    if (!parent) return;

    const w = parent.clientWidth;
    const h = parent.clientHeight;

    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoom, this.zoom);

    const pulse = (Math.sin(this.animTime * 0.004) + 1) / 2; // 0..1 pulse

    // 1. Draw Edges with Directional Flow
    for (const edge of this.filteredGraph.edges) {
      const p1 = this.nodePositions.get(edge.source);
      const p2 = this.nodePositions.get(edge.target);
      if (!p1 || !p2) continue;

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);

      if (edge.in_attack_path) {
        ctx.strokeStyle = '#f43f5e';
        ctx.lineWidth = 2.5;
        ctx.shadowColor = 'rgba(244, 63, 94, 0.7)';
        ctx.shadowBlur = 8 + pulse * 6;
      } else {
        ctx.strokeStyle = '#26334d';
        ctx.lineWidth = 1.4;
      }
      ctx.stroke();
      ctx.restore();

      // Flowing Energy Particle for active attack path
      if (edge.in_attack_path) {
        const t = ((this.animTime * 0.001) % 1.5) / 1.5;
        const px = p1.x + (p2.x - p1.x) * t;
        const py = p1.y + (p2.y - p1.y) * t;

        ctx.save();
        ctx.beginPath();
        ctx.arc(px, py, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = '#f43f5e';
        ctx.shadowBlur = 10;
        ctx.fill();
        ctx.restore();
      }

      // Relation Tag badge
      if (edge.relation) {
        const mx = (p1.x + p2.x) / 2;
        const my = (p1.y + p2.y) / 2;
        ctx.save();
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.fillStyle = edge.in_attack_path ? '#fda4af' : '#94a3b8';
        ctx.textAlign = 'center';
        ctx.fillText(edge.relation, mx, my - 5);
        ctx.restore();
      }
    }

    // 2. Draw Nodes
    for (const node of this.filteredGraph.nodes) {
      const pos = this.nodePositions.get(node.id);
      if (!pos) continue;

      const isSelected = this.selectedNode && this.selectedNode.id === node.id;
      const isHovered = this.hoveredNode && this.hoveredNode.id === node.id;
      const r = node.type === 'host' ? 24 : (node.type === 'finding' ? 20 : 17);

      ctx.save();

      // Outer Neon Pulsing Aura for Attack Nodes
      if (node.in_attack_path) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, r + 7 + pulse * 4, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(244, 63, 94, ${0.25 + pulse * 0.35})`;
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Selection Halo
      if (isSelected) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, r + 5, 0, Math.PI * 2);
        ctx.strokeStyle = '#38bdf8';
        ctx.lineWidth = 2.5;
        ctx.shadowColor = 'rgba(56, 189, 248, 0.8)';
        ctx.shadowBlur = 10;
        ctx.stroke();
      }

      // Node Body Gradient
      const grad = ctx.createRadialGradient(pos.x - r * 0.3, pos.y - r * 0.3, 2, pos.x, pos.y, r);
      if (node.in_attack_path || node.severity === 'critical') {
        grad.addColorStop(0, '#fb7185');
        grad.addColorStop(1, '#e11d48');
      } else if (node.type === 'host') {
        grad.addColorStop(0, '#38bdf8');
        grad.addColorStop(1, '#0284c7');
      } else if (node.type === 'network') {
        grad.addColorStop(0, '#c084fc');
        grad.addColorStop(1, '#7e22ce');
      } else if (node.type === 'finding') {
        grad.addColorStop(0, '#fbbf24');
        grad.addColorStop(1, '#d97706');
      } else {
        grad.addColorStop(0, node.state === 'suspicious' ? '#fb7185' : '#34d399');
        grad.addColorStop(1, node.state === 'suspicious' ? '#e11d48' : '#059669');
      }

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.shadowColor = node.in_attack_path ? 'rgba(244, 63, 94, 0.6)' : 'rgba(0, 0, 0, 0.5)';
      ctx.shadowBlur = isHovered ? 12 : 6;
      ctx.fill();

      // Node Crisp Border
      ctx.lineWidth = isSelected ? 2.5 : (isHovered ? 2 : 1.5);
      ctx.strokeStyle = isSelected ? '#ffffff' : (isHovered ? '#38bdf8' : 'rgba(255, 255, 255, 0.3)');
      ctx.stroke();

      // Glyph Icon
      ctx.font = '12px sans-serif';
      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const icon = node.type === 'host' ? '💻' : (node.type === 'process' ? '⚙️' : (node.type === 'finding' ? '⚠️' : '⛓️'));
      ctx.fillText(icon, pos.x, pos.y);

      // Label Capsule
      ctx.font = '600 11px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
      ctx.fillStyle = '#f8fafc';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(node.label || node.id, pos.x, pos.y + r + 5);

      if (node.subtitle) {
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.fillStyle = '#94a3b8';
        ctx.fillText(node.subtitle, pos.x, pos.y + r + 19);
      }

      ctx.restore();
    }

    ctx.restore();
    this.drawMinimap();
  }

  drawMinimap() {
    if (!this.minimapCtx || !this.minimapCanvas) return;
    const mctx = this.minimapCtx;
    const mw = this.minimapCanvas.width;
    const mh = this.minimapCanvas.height;

    mctx.clearRect(0, 0, mw, mh);

    const nodes = this.filteredGraph.nodes;
    if (nodes.length === 0) return;

    // Center thumbnail
    const parent = this.canvas ? this.canvas.parentElement : null;
    const cw = parent ? parent.clientWidth : 800;
    const ch = parent ? parent.clientHeight : 500;

    const scaleX = mw / (cw * 2);
    const scaleY = mh / (ch * 2);

    for (const node of nodes) {
      const pos = this.nodePositions.get(node.id);
      if (!pos) continue;

      const mx = mw / 2 + (pos.x - cw / 2) * scaleX;
      const my = mh / 2 + (pos.y - ch / 2) * scaleY;

      mctx.beginPath();
      mctx.arc(mx, my, node.in_attack_path ? 3 : 2, 0, Math.PI * 2);
      mctx.fillStyle = node.in_attack_path ? '#f43f5e' : '#38bdf8';
      mctx.fill();
    }
  }
}
