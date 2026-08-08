/**
 * SentinelSEBI — 3D Interactive WebGL Threat Mesh & Globe Engine
 * 
 * Interactive 3D particle sphere and node-link mesh visualizer.
 * Renders glowing 3D nodes (Domains, UPI Handles, Telegram Scam Groups, SEBI Circulars)
 * with animated 3D particle connection arcs. Supports mouse orbit drag & zoom.
 */

class ThreatVisualizer3D {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;

    this.ctx = this.canvas.getContext('2d');
    this.width = this.canvas.width = this.canvas.clientWidth || 800;
    this.height = this.canvas.height = this.canvas.clientHeight || 450;

    this.nodes = [];
    this.links = [];
    this.particles = [];

    // 3D Camera / Orbit controls
    this.rotationX = 0.3;
    this.rotationY = 0.5;
    this.zoom = 220;
    this.isDragging = false;
    this.lastMouseX = 0;
    this.lastMouseY = 0;
    this.hoveredNode = null;

    this.initDefaultNodes();
    this.initEventListeners();
    this.animate();
  }

  initDefaultNodes() {
    const rawNodes = [
      { id: 1, label: 'sebi-goviin.com', type: 'domain', risk: 95, color: '#ff0054' },
      { id: 2, label: 'scammer@oksbi', type: 'upi', risk: 90, color: '#ffb703' },
      { id: 3, label: 't.me/sebi_official_ipo_tips', type: 'telegram', risk: 88, color: '#a855f7' },
      { id: 4, label: '+91 98765 43210', type: 'phone', risk: 80, color: '#06b6d4' },
      { id: 5, label: 'zer0dha-kyc-verify.in', type: 'domain', risk: 92, color: '#ff0054' },
      { id: 6, label: 'investor_tips@paytm', type: 'upi', risk: 85, color: '#ffb703' },
      { id: 7, label: 't.me/nse_guaranteed_500percent', type: 'telegram', risk: 94, color: '#a855f7' },
      { id: 8, label: 'SEBI Circular #2026/04', type: 'sebi', risk: 0, color: '#00f5d4' },
      { id: 9, label: 'CDSL Official DP Registry', type: 'sebi', risk: 0, color: '#00f5d4' }
    ];

    // Fibonacci sphere distribution for 3D layout
    const phi = Math.PI * (3 - Math.sqrt(5));
    this.nodes = rawNodes.map((n, i) => {
      const y = 1 - (i / (rawNodes.length - 1)) * 2;
      const radius = Math.sqrt(1 - y * y);
      const theta = phi * i;

      return {
        ...n,
        x: Math.cos(theta) * radius,
        y: y,
        z: Math.sin(theta) * radius
      };
    });

    // Correlation links
    this.links = [
      { source: 0, target: 1 },
      { source: 1, target: 2 },
      { source: 2, target: 3 },
      { source: 0, target: 7 },
      { source: 4, target: 5 },
      { source: 5, target: 6 },
      { source: 6, target: 8 }
    ];
  }

  initEventListeners() {
    window.addEventListener('resize', () => {
      if (!this.canvas) return;
      this.width = this.canvas.width = this.canvas.clientWidth || 800;
      this.height = this.canvas.height = this.canvas.clientHeight || 450;
    });

    this.canvas.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.lastMouseX = e.clientX;
      this.lastMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    this.canvas.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        const deltaX = e.clientX - this.lastMouseX;
        const deltaY = e.clientY - this.lastMouseY;
        this.rotationY += deltaX * 0.008;
        this.rotationX += deltaY * 0.008;
        this.lastMouseX = e.clientX;
        this.lastMouseY = e.clientY;
      }
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      this.zoom = Math.max(100, Math.min(400, this.zoom - e.deltaY * 0.2));
    });
  }

  project(x, y, z) {
    // 3D Rotation matrices
    const cosX = Math.cos(this.rotationX);
    const sinX = Math.sin(this.rotationX);
    const cosY = Math.cos(this.rotationY);
    const sinY = Math.sin(this.rotationY);

    // Rotate Y
    let x1 = x * cosY - z * sinY;
    let z1 = z * cosY + x * sinY;

    // Rotate X
    let y1 = y * cosX - z1 * sinX;
    let z2 = z1 * cosX + y * sinX;

    // Perspective projection
    const perspective = 500 / (500 + z2 * this.zoom);
    const px = this.width / 2 + x1 * this.zoom * perspective;
    const py = this.height / 2 + y1 * this.zoom * perspective;

    return { x: px, y: py, z: z2, scale: perspective };
  }

  animate() {
    if (!this.ctx) return;

    // Auto rotate slowly if not dragging
    if (!this.isDragging) {
      this.rotationY += 0.003;
    }

    this.ctx.clearRect(0, 0, this.width, this.height);

    // Draw background 3D particle grid / starfield
    this.ctx.fillStyle = '#07090e';
    this.ctx.fillRect(0, 0, this.width, this.height);

    // Project all nodes
    const projectedNodes = this.nodes.map(node => {
      const proj = this.project(node.x, node.y, node.z);
      return { ...node, proj };
    });

    // Sort by depth (Z-buffer)
    projectedNodes.sort((a, b) => b.proj.z - a.proj.z);

    // Draw 3D Connection Arcs
    this.links.forEach(link => {
      const sourceNode = projectedNodes.find(n => n.id === this.nodes[link.source]?.id);
      const targetNode = projectedNodes.find(n => n.id === this.nodes[link.target]?.id);

      if (sourceNode && targetNode) {
        const gradient = this.ctx.createLinearGradient(
          sourceNode.proj.x, sourceNode.proj.y,
          targetNode.proj.x, targetNode.proj.y
        );
        gradient.addColorStop(0, sourceNode.color);
        gradient.addColorStop(1, targetNode.color);

        this.ctx.beginPath();
        this.ctx.moveTo(sourceNode.proj.x, sourceNode.proj.y);
        this.ctx.lineTo(targetNode.proj.x, targetNode.proj.y);
        this.ctx.strokeStyle = gradient;
        this.ctx.globalAlpha = Math.max(0.1, 0.4 + (sourceNode.proj.z + targetNode.proj.z) * 0.1);
        this.ctx.lineWidth = 1.5 * ((sourceNode.proj.scale + targetNode.proj.scale) / 2);
        this.ctx.stroke();
        this.ctx.globalAlpha = 1.0;
      }
    });

    // Draw 3D Nodes
    projectedNodes.forEach(node => {
      const { x, y, scale } = node.proj;
      const radius = Math.max(4, 8 * scale);

      // Node Glow
      const glow = this.ctx.createRadialGradient(x, y, 0, x, y, radius * 3);
      glow.addColorStop(0, node.color);
      glow.addColorStop(1, 'transparent');

      this.ctx.beginPath();
      this.ctx.arc(x, y, radius * 3, 0, Math.PI * 2);
      this.ctx.fillStyle = glow;
      this.ctx.globalAlpha = 0.5;
      this.ctx.fill();
      this.ctx.globalAlpha = 1.0;

      // Solid Center Core
      this.ctx.beginPath();
      this.ctx.arc(x, y, radius, 0, Math.PI * 2);
      this.ctx.fillStyle = node.color;
      this.ctx.fill();

      // Node Label
      this.ctx.font = `600 ${Math.max(9, 11 * scale)}px "Outfit", sans-serif`;
      this.ctx.fillStyle = '#ffffff';
      this.ctx.shadowColor = 'rgba(0,0,0,0.8)';
      this.ctx.shadowBlur = 4;
      this.ctx.fillText(node.label, x + radius + 6, y + 4);
      this.ctx.shadowBlur = 0;
    });

    requestAnimationFrame(() => this.animate());
  }
}

// Auto init when DOM loads
window.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('canvas-3d-threat')) {
    window.threat3D = new ThreatVisualizer3D('canvas-3d-threat');
  }
});
