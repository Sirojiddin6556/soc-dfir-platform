/**
 * Layer Engine: Dynamic projections of a single investigation graph
 */
export function filterGraphByLayer(graph, layer) {
  if (!graph || !graph.nodes) return { nodes: [], edges: [] };

  switch (layer) {
    case 'environment': {
      const allowedNodeTypes = ['host', 'network', 'service'];
      const allowedEdgeRel = ['connected_to', 'routes_to', 'hosts'];
      const nodes = graph.nodes.filter(n => allowedNodeTypes.includes(n.type));
      const nodeIds = new Set(nodes.map(n => n.id));
      const edges = graph.edges.filter(e => allowedEdgeRel.includes(e.relation) && nodeIds.has(e.source) && nodeIds.has(e.target));
      return { nodes, edges };
    }

    case 'processes': {
      const allowedNodeTypes = ['host', 'process'];
      const nodes = graph.nodes.filter(n => allowedNodeTypes.includes(n.type));
      const nodeIds = new Set(nodes.map(n => n.id));
      const edges = graph.edges.filter(e => ['runs', 'spawned'].includes(e.relation) && nodeIds.has(e.source) && nodeIds.has(e.target));
      return { nodes, edges };
    }

    case 'network': {
      const allowedNodeTypes = ['host', 'process', 'network', 'ip', 'socket'];
      const nodes = graph.nodes.filter(n => allowedNodeTypes.includes(n.type));
      const nodeIds = new Set(nodes.map(n => n.id));
      const edges = graph.edges.filter(e => ['connects_to', 'resolves_to', 'runs'].includes(e.relation) && nodeIds.has(e.source) && nodeIds.has(e.target));
      return { nodes, edges };
    }

    case 'mitre': {
      const allowedNodeTypes = ['host', 'finding', 'process'];
      const nodes = graph.nodes.filter(n => allowedNodeTypes.includes(n.type) && (n.in_attack_path || n.type === 'finding'));
      const nodeIds = new Set(nodes.map(n => n.id));
      const edges = graph.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
      return { nodes, edges };
    }

    case 'attack':
    default: {
      const nodes = graph.nodes.filter(n => n.in_attack_path || n.severity === 'high' || n.severity === 'critical');
      const nodeIds = new Set(nodes.map(n => n.id));
      const edges = graph.edges.filter(e => (e.in_attack_path || (nodeIds.has(e.source) && nodeIds.has(e.target))));
      return { nodes, edges };
    }
  }
}
