export class InvestigationStore {
  constructor() {
    this.case = null;
    this.assets = [];
    this.processes = [];
    this.connections = [];
    this.findings = [];
    this.autoruns = [];
    this.metrics = { findings: 0, evidence: 0, assets: 0 };
    this.timeline = [];
    this.graph = {
      nodes: [],
      edges: []
    };
    this.mitre = [];
    this.selectedEntity = null;
    this.activeLayer = 'attack';
  }

  update(snapshot) {
    this.case = snapshot.case ?? this.case;
    this.assets = snapshot.assets ?? [];
    this.processes = snapshot.processes ?? [];
    this.connections = snapshot.connections ?? [];
    this.findings = snapshot.findings ?? [];
    this.autoruns = snapshot.autoruns ?? [];
    this.metrics = snapshot.metrics ?? {
      findings: this.findings.length,
      evidence: 0,
      assets: this.assets.length
    };
    this.timeline = snapshot.timeline ?? [];
    this.graph = snapshot.graph ?? { nodes: [], edges: [] };
    this.mitre = snapshot.mitre ?? [];
  }

  selectEntity(entity) {
    this.selectedEntity = entity;
  }

  setLayer(layer) {
    this.activeLayer = layer;
  }
}
