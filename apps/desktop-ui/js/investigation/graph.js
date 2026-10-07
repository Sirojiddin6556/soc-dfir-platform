import { filterGraphByLayer } from './layers.js';
import { escapeHtml } from '../util/html.js';

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

    this.nodePositions.clear();

    const hostNodes = nodes.filter(n => n.type === 'host');
    const findNodes = nodes.filter(n => n.type === 'finding');
    // Processes and network sockets share one set of concentric arcs fanning
    // out to the right of the host. A single placement function for every
    // non-host, non-finding node -- regardless of type or attack-path status
    // -- means different layers/filters can never assign two node types to
    // the same screen position, and confining the fan to the host's right
    // side (instead of a full 360° circle) means a ring can never wrap back
    // around and collide with the host itself.
    const orbitNodes = nodes.filter(n => n.type !== 'host' && n.type !== 'finding');

    const fixed = new Set();
    const originX = Math.min(280, width * 0.22);
    const originY = height / 2;
    hostNodes.forEach((n, i) => {
      this.nodePositions.set(n.id, { x: originX + i * 220, y: originY });
      fixed.add(n.id);
    });

    // Seed positions on an even grid to the right of the host instead of an
    // angular fan. A fan's rings necessarily converge back together near its
    // two extreme angles (cos/sin both shrink the further out you go), which
    // recreated the same "several nodes on top of each other" problem right
    // at the top and bottom edges once enough nodes were on one host (e.g.
    // the Сеть layer with every process *and* every socket). A grid has no
    // such convergence point: spacing between any two neighbours stays
    // uniform no matter how many nodes there are, so it only gets tighter
    // (never collapses) as the node count grows. Alternate rows are
    // staggered by half a cell purely so the result doesn't read as rigid
    // vertical columns once the host-to-node lines are drawn through it.
    const availableWidth = Math.max(200, width - originX - 60);
    const availableHeight = Math.max(160, height - 60);
    const n = orbitNodes.length;
    const cols = Math.max(1, Math.round(Math.sqrt(n * (availableWidth / availableHeight))));
    const rows = Math.max(1, Math.ceil(n / cols));
    const cellW = availableWidth / cols;
    const cellH = availableHeight / rows;
    const gridStartX = originX + 50;
    const gridStartY = originY - availableHeight / 2;

    orbitNodes.forEach((node, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const staggerX = (row % 2) * (cellW / 2);
      this.nodePositions.set(node.id, {
        x: gridStartX + staggerX + col * cellW + cellW / 2,
        y: gridStartY + row * cellH + cellH / 2
      });
    });

    // Findings sit in a column to the left of the host, wrapping into extra
    // columns (rather than a fixed 55px step) once there are too many to fit
    // the canvas height -- otherwise the later findings in a case with many
    // of them silently render below the visible area.
    const findColCount = Math.max(1, Math.ceil((findNodes.length * 55) / availableHeight));
    const findPerCol = Math.ceil(findNodes.length / findColCount);
    const findRowGap = Math.min(55, availableHeight / Math.max(1, findPerCol));
    findNodes.forEach((n, i) => {
      const col = Math.floor(i / findPerCol);
      const row = i % findPerCol;
      this.nodePositions.set(n.id, {
        x: Math.max(40, originX - 200 - col * 130),
        y: Math.min(height - 40, originY + 100 + row * findRowGap)
      });
      fixed.add(n.id);
    });

    // The arc above is only a starting guess. However many nodes land on a
    // host, a short collision-relaxation pass (the same idea as d3's
    // forceCollide) pushes any two circles that are still touching apart
    // until none overlap, so labels stay readable regardless of node count.
    this.resolveCollisions(nodes, fixed, width, height);
  }

  nodeCollisionRadius(node) {
    const base = node.type === 'host' ? 26 : (node.type === 'finding' ? 20 : 18);
    // Padding approximates the label rendered under the circle so two nodes
    // stop before their labels touch, not just before their circles do. The
    // circle itself is small and constant, but labels like "IntelCpHDCPSvc.exe"
    // or "TCP:49674" are wide, so scale the padding with label length instead
    // of a flat constant -- otherwise long names still collide visually even
    // when the circles themselves have cleared each other.
    const label = String(node.label || node.id || '');
    const subtitle = String(node.subtitle || '');
    const textHalfWidth = (Math.max(label.length, subtitle.length) * 5.4) / 2;
    return base + Math.max(34, textHalfWidth + 12);
  }

  resolveCollisions(nodes, fixed, width, height) {
    const iterations = 120;
    const padding = 6;

    for (let pass = 0; pass < iterations; pass++) {
      let moved = false;

      for (let i = 0; i < nodes.length; i++) {
        const posA = this.nodePositions.get(nodes[i].id);
        if (!posA) continue;

        for (let j = i + 1; j < nodes.length; j++) {
          const posB = this.nodePositions.get(nodes[j].id);
          if (!posB) continue;

          const dx = posB.x - posA.x;
          const dy = posB.y - posA.y;
          let dist = Math.hypot(dx, dy);
          const minDist = this.nodeCollisionRadius(nodes[i]) + this.nodeCollisionRadius(nodes[j]) + padding;

          if (dist < minDist) {
            moved = true;
            if (dist < 0.001) {
              dist = 0.001;
            }
            const overlap = (minDist - dist) / 2;
            const ux = dx / dist;
            const uy = dy / dist;
            const aFixed = fixed.has(nodes[i].id);
            const bFixed = fixed.has(nodes[j].id);

            if (!aFixed && !bFixed) {
              posA.x -= ux * overlap;
              posA.y -= uy * overlap;
              posB.x += ux * overlap;
              posB.y += uy * overlap;
            } else if (!aFixed) {
              posA.x -= ux * overlap * 2;
              posA.y -= uy * overlap * 2;
            } else if (!bFixed) {
              posB.x += ux * overlap * 2;
              posB.y += uy * overlap * 2;
            }
          }
        }
      }

      if (!moved) break;
    }

    const margin = 40;
    for (const node of nodes) {
      if (fixed.has(node.id)) continue;
      const pos = this.nodePositions.get(node.id);
      if (!pos) continue;
      pos.x = Math.min(width - margin, Math.max(margin, pos.x));
      pos.y = Math.min(height - margin, Math.max(margin, pos.y));
    }
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
        <span>${escapeHtml(node.label || node.id)}</span>
        <span class="badge ${node.in_attack_path ? 'badge-critical' : 'badge-net'}" style="margin-left: auto; font-size: 8px;">${escapeHtml(String(node.type ?? '').toUpperCase())}</span>
      </div>
      <div class="graph-tooltip-detail">
        <div>ID: <strong style="color: #f8fafc;">${escapeHtml(node.id)}</strong></div>
        ${node.subtitle ? `<div>Инфо: ${escapeHtml(node.subtitle)}</div>` : ''}
        ${node.path ? `<div>Путь: ${escapeHtml(node.path)}</div>` : ''}
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
