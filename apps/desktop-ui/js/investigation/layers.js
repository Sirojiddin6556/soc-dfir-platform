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
      // A process only belongs on the network layer if it actually owns a
      // socket -- otherwise every process on the host (most of which never
      // touch the network) showed up here just because its type matched,
      // which is why this view looked like "all entities" instead of the
      // network topology.
      const connectedProcIds = new Set(
        graph.edges.filter(e => e.relation === 'connects_to').map(e => e.source)
      );
      const nodes = graph.nodes.filter(n =>
        n.type === 'host' ||
        n.type === 'network' ||
        n.type === 'ip' ||
        n.type === 'socket' ||
        (n.type === 'process' && connectedProcIds.has(n.id))
      );
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
