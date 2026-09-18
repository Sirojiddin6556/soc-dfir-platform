export class InvestigationStore {
  constructor() {
    this.case = null;
    this.assets = [];
    this.processes = [];
    this.connections = [];
    this.findings = [];
    this.evidence = [];
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
    this.evidence = snapshot.evidence ?? [];
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
