import { filterGraphByLayer } from './layers.js';

export class InvestigationGraph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas ? canvas.getContext('2d') : null;
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
    this.initEvents();
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
          this.draw();
        }
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.setZoom(this.zoom * zoomFactor);
    });
  }

  resizeCanvas() {
    if (!this.canvas) return;
    const parent = this.canvas.parentElement;
    if (!parent) return;
    this.canvas.width = parent.clientWidth * window.devicePixelRatio;
    this.canvas.height = parent.clientHeight * window.devicePixelRatio;
    if (this.ctx) {
      this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    }
    this.draw();
  }

  setZoom(val) {
    this.zoom = Math.max(0.3, Math.min(3.0, val));
    const label = document.getElementById('zoomLabel');
    if (label) label.textContent = `${Math.round(this.zoom * 100)}%`;
    this.draw();
  }

  resetView() {
    this.zoom = 1.0;
    this.panX = (this.canvas ? this.canvas.parentElement.clientWidth / 2 : 400) - 200;
    this.panY = (this.canvas ? this.canvas.parentElement.clientHeight / 2 : 300) - 150;
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

    const width = this.canvas ? this.canvas.parentElement.clientWidth : 800;
    const height = this.canvas ? this.canvas.parentElement.clientHeight : 500;
    const centerX = width / 2;
    const centerY = height / 2;

    this.nodePositions.clear();

    const hostNodes = nodes.filter(n => n.type === 'host');
    const procNodes = nodes.filter(n => n.type === 'process');
    const netNodes = nodes.filter(n => n.type === 'network');
    const findNodes = nodes.filter(n => n.type === 'finding');

    hostNodes.forEach((n, i) => {
      this.nodePositions.set(n.id, { x: centerX - 180 + i * 200, y: centerY - 100 });
    });

    procNodes.forEach((n, i) => {
      const angle = (i / Math.max(1, procNodes.length)) * Math.PI * 2;
      const radius = 150 + (i % 2) * 50;
      this.nodePositions.set(n.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      });
    });

    netNodes.forEach((n, i) => {
      const angle = (i / Math.max(1, netNodes.length)) * Math.PI * 1.5;
      this.nodePositions.set(n.id, {
        x: centerX + 260 + Math.cos(angle) * 120,
        y: centerY + Math.sin(angle) * 120
      });
    });

    findNodes.forEach((n, i) => {
      this.nodePositions.set(n.id, {
        x: centerX - 260 + (i % 2) * 40,
        y: centerY + 60 + i * 50
      });
    });
  }

  hitTest(x, y) {
    for (const node of this.filteredGraph.nodes) {
      const pos = this.nodePositions.get(node.id);
      if (!pos) continue;
      const r = node.type === 'host' ? 24 : 18;
      const dist = Math.hypot(pos.x - x, pos.y - y);
      if (dist <= r) return node;
    }
    return null;
  }

  draw() {
    if (!this.ctx || !this.canvas) return;
    const ctx = this.ctx;
    const w = this.canvas.parentElement.clientWidth;
    const h = this.canvas.parentElement.clientHeight;

    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoom, this.zoom);

    // Draw Edges
    for (const edge of this.filteredGraph.edges) {
      const p1 = this.nodePositions.get(edge.source);
      const p2 = this.nodePositions.get(edge.target);
      if (!p1 || !p2) continue;

      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);

      if (edge.in_attack_path) {
        ctx.strokeStyle = '#f85149';
        ctx.lineWidth = 2.5;
      } else {
        ctx.strokeStyle = '#30363d';
        ctx.lineWidth = 1.2;
      }
      ctx.stroke();

      // Draw relation label
      if (edge.relation) {
        const mx = (p1.x + p2.x) / 2;
        const my = (p1.y + p2.y) / 2;
        ctx.font = '9px monospace';
        ctx.fillStyle = edge.in_attack_path ? '#ff7b72' : '#8b949e';
        ctx.textAlign = 'center';
        ctx.fillText(edge.relation, mx, my - 4);
      }
    }

    // Draw Nodes
    for (const node of this.filteredGraph.nodes) {
      const pos = this.nodePositions.get(node.id);
      if (!pos) continue;

      const isSelected = this.selectedNode && this.selectedNode.id === node.id;
      const isHovered = this.hoveredNode && this.hoveredNode.id === node.id;
      const r = node.type === 'host' ? 22 : 16;

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);

      // Node Colors
      if (node.in_attack_path || node.severity === 'critical') {
        ctx.fillStyle = '#f85149';
      } else if (node.type === 'host') {
        ctx.fillStyle = '#58a6ff';
      } else if (node.type === 'network') {
        ctx.fillStyle = '#bc8cff';
      } else if (node.type === 'finding') {
        ctx.fillStyle = '#d29922';
      } else {
        ctx.fillStyle = node.state === 'suspicious' ? '#f85149' : '#238636';
      }
      ctx.fill();

      // Border & Selection Halo
      ctx.lineWidth = isSelected ? 3 : (isHovered ? 2 : 1);
      ctx.strokeStyle = isSelected ? '#ffffff' : (isHovered ? '#58a6ff' : '#0d1117');
      ctx.stroke();

      if (isSelected) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, r + 6, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(88, 166, 255, 0.4)';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Icon / Label
      ctx.font = '10px sans-serif';
      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const icon = node.type === 'host' ? '💻' : (node.type === 'process' ? '⚙️' : (node.type === 'finding' ? '⚠️' : '⛓️'));
      ctx.fillText(icon, pos.x, pos.y);

      // Subtitle below node
      ctx.font = '11px sans-serif';
      ctx.fillStyle = '#f0f6fc';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(node.label || node.id, pos.x, pos.y + r + 4);

      if (node.subtitle) {
        ctx.font = '9px monospace';
        ctx.fillStyle = '#8b949e';
        ctx.fillText(node.subtitle, pos.x, pos.y + r + 17);
      }
    }

    ctx.restore();
  }
}
