package correlation

// topologyHTMLHead contains the HTML head and body structure for the interactive
// topology viewer. It is concatenated with D3, JSON data, and topologyHTMLJS at runtime.
const topologyHTMLHead = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Topology Viewer</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; }
.header { background: #16213e; padding: 12px 20px; border-bottom: 1px solid #0f3460; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 18px; color: #e94560; }
.tabs { display: flex; gap: 2px; background: #16213e; padding: 0 20px; border-bottom: 1px solid #0f3460; flex-wrap: wrap; }
.tab { padding: 8px 16px; cursor: pointer; border: none; background: transparent; color: #a0a0a0; font-size: 13px; transition: all 0.2s; }
.tab:hover { color: #e0e0e0; background: #1a1a3e; }
.tab.active { color: #e94560; border-bottom: 2px solid #e94560; background: #1a1a3e; }
.tab .badge { background: #0f3460; color: #aaa; font-size: 11px; padding: 1px 6px; border-radius: 8px; margin-left: 4px; }
.tab.active .badge { background: #e94560; color: #fff; }
.toolbar { display: flex; gap: 10px; padding: 8px 20px; background: #16213e; border-bottom: 1px solid #0f3460; align-items: center; flex-wrap: wrap; }
.toolbar input[type="text"] { background: #0f3460; border: 1px solid #1a1a4e; color: #e0e0e0; padding: 4px 10px; border-radius: 4px; font-size: 13px; width: 200px; }
.toolbar input::placeholder { color: #666; }
.toolbar label { font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 4px; color: #aaa; }
.toolbar input[type="checkbox"] { width: auto; }
.toolbar select { background: #0f3460; border: 1px solid #1a1a4e; color: #e0e0e0; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
#graph-container { width: 100%; height: calc(100vh - 140px); overflow: hidden; }
#graph-container svg { width: 100%; height: 100%; }

/* Detail panel */
.detail-panel { position: fixed; right: -420px; top: 0; bottom: 0; width: 400px; background: #16213e; border-left: 1px solid #0f3460; padding: 20px; transition: right 0.3s ease; overflow-y: auto; z-index: 100; }
.detail-panel.open { right: 0; }
.close-btn { position: absolute; top: 10px; right: 10px; background: none; border: none; color: #e94560; font-size: 18px; cursor: pointer; }
.detail-panel h2 { color: #e94560; margin-bottom: 8px; font-size: 16px; }
.detail-panel h3 { color: #e94560; margin: 14px 0 8px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
.detail-panel .field { margin-bottom: 6px; font-size: 13px; }
.detail-panel .field .label { color: #888; min-width: 90px; display: inline-block; }
.detail-panel .field .value { color: #e0e0e0; }

/* Risk badge */
.risk-badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 12px; font-weight: bold; margin-bottom: 8px; }
.risk-low { background: #1b5e20; color: #a5d6a7; }
.risk-medium { background: #f57f17; color: #fff3e0; }
.risk-high { background: #e65100; color: #ffe0b2; }
.risk-critical { background: #b71c1c; color: #ffcdd2; }

/* Risk breakdown bar */
.risk-bar { height: 8px; border-radius: 4px; background: #333; margin: 6px 0; overflow: hidden; display: flex; }
.risk-bar-segment { height: 100%; transition: width 0.3s; }

/* Ports table */
.ports-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 4px; }
.ports-table th { text-align: left; color: #888; padding: 4px 6px; border-bottom: 1px solid #0f3460; font-weight: normal; }
.ports-table td { padding: 3px 6px; border-bottom: 1px solid #1a1a3e; }

/* Vulnerability list */
.vuln-item { padding: 6px 8px; margin: 4px 0; border-radius: 4px; font-size: 12px; border-left: 3px solid; }
.vuln-critical { background: #b71c1c22; border-color: #b71c1c; }
.vuln-high { background: #e6510022; border-color: #e65100; }
.vuln-medium { background: #f57f1722; border-color: #f57f17; }
.vuln-low { background: #1b5e2022; border-color: #1b5e20; }
.vuln-info { background: #0d47a122; border-color: #0d47a1; }
.vuln-severity { font-weight: bold; text-transform: uppercase; font-size: 10px; margin-right: 6px; }

/* Recommendations */
.rec-item { font-size: 12px; padding: 3px 0; color: #bbb; }
.rec-item::before { content: "\2022"; color: #e94560; margin-right: 6px; }

/* Legend */
.legend { position: fixed; bottom: 10px; left: 10px; background: #16213eDD; padding: 10px 14px; border-radius: 6px; font-size: 11px; z-index: 50; }
.legend-item { display: flex; align-items: center; gap: 6px; margin: 3px 0; }
.legend-color { width: 12px; height: 12px; border-radius: 3px; }

/* D3 graph styles */
.node { cursor: pointer; }
.node circle { stroke-width: 2; transition: r 0.2s; }
.node:hover circle { stroke-width: 3; }
.node text { pointer-events: none; text-anchor: middle; }
.node .node-label { font-size: 11px; fill: #e0e0e0; }
.node .node-sub { font-size: 8px; fill: #888; text-transform: uppercase; letter-spacing: 0.3px; }
.node.gateway circle { stroke-dasharray: none; }
.link { stroke-opacity: 0.4; }
.link.gateway { stroke-dasharray: 6,3; }
.link.physical { stroke-opacity: 0.7; stroke-width: 2; }
.link-label { font-size: 9px; fill: #64B5F6; pointer-events: none; }
.compliance-ring { fill: none; pointer-events: none; }
.compliance-section h3 { color: #e94560; margin: 14px 0 8px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
.compliance-item { font-size: 12px; margin: 3px 0; }
.vlan-hull { fill-opacity: 0.06; stroke-opacity: 0.3; stroke-width: 1.5; }
.vlan-label { font-size: 13px; fill: #888; font-weight: bold; }
.node.remote circle { stroke-dasharray: 4,2; }
.node.local circle { stroke-dasharray: none; }
.node.highlighted circle { stroke: #fff !important; stroke-width: 3 !important; }
.node.dimmed { opacity: 0.2; }
</style>
</head>
<body>
<div class="header">
  <h1>Network Topology Viewer</h1>
  <div style="font-size:12px;color:#888" id="stats"></div>
</div>
<div class="tabs" id="tab-bar"></div>
<div class="toolbar" id="toolbar"></div>
<div id="graph-container"></div>
<div class="detail-panel" id="detail-panel">
  <button class="close-btn" onclick="closeDetail()">&times;</button>
  <div id="detail-content"></div>
</div>
<div class="legend" id="legend"></div>
<script>
// ─── Data (injected by Go) ────────────────────────────────────
`

// topologyHTMLJS contains the JavaScript logic for the interactive topology viewer.
// It is concatenated after the JSON data injection point.
const topologyHTMLJS = `;
'use strict';

// ─── Primary categories (match TUI: linux, windows, network_device, unknown) ──
const CAT_COLORS = {
  network_device: '#2196F3',
  windows: '#4CAF50',
  linux: '#FF9800',
  unknown: '#9E9E9E'
};
const CAT_LABELS = {
  network_device: 'Network Device',
  windows: 'Windows',
  linux: 'Linux',
  unknown: 'Unknown'
};

// Sub-type label computed by the Go correlator from os_match, vendor,
// sys_description, and port data. Displayed as secondary text on nodes.
function hostSubtype(h) {
  if (h.attributes && h.attributes.host_subtype) return h.attributes.host_subtype;
  var dt = (h.device_type || '').toLowerCase();
  if (dt && dt !== h.category && dt !== 'unknown' && dt !== 'general purpose' && dt !== 'specialized' && dt !== 'other') return dt;
  return '';
}

const VLAN_COLORS = [
  '#e94560','#2196F3','#4CAF50','#FF9800','#9C27B0',
  '#00BCD4','#FFEB3B','#795548','#607D8B','#E91E63',
  '#3F51B5','#8BC34A','#FF5722','#673AB7','#009688'
];
const SEV_COLORS = {
  critical: '#b71c1c',
  high: '#e65100',
  medium: '#f57f17',
  low: '#1b5e20',
  info: '#0d47a1'
};

// ─── State ────────────────────────────────────────────────────
const state = {
  currentTab: 'overview',
  simulation: null,
  filters: { network_device: true, windows: true, linux: true, unknown: true },
  searchText: '',
  serviceFilter: '',
  riskThreshold: 0,
  selectedHost: null,
  showSameVlanEdges: false
};

// ─── Build flat host list ─────────────────────────────────────
function allHosts() {
  var hosts = [];
  VLANS.forEach(function(v) {
    v.hosts.forEach(function(h) {
      h._vlanId = v.id;
      h._vlanName = v.name;
      hosts.push(h);
    });
  });
  return hosts;
}

function filteredHosts(vlanId) {
  var hosts = [];
  var vlans = vlanId ? VLANS.filter(function(v){ return v.id === vlanId; }) : VLANS;
  vlans.forEach(function(v) {
    v.hosts.forEach(function(h) {
      if (!state.filters[h.category]) return;
      if (state.searchText) {
        var s = state.searchText.toLowerCase();
        if (h.ip.toLowerCase().indexOf(s) < 0 &&
            (h.hostname || '').toLowerCase().indexOf(s) < 0 &&
            (h.vendor || '').toLowerCase().indexOf(s) < 0) return;
      }
      if (state.serviceFilter) {
        var sf = state.serviceFilter.toLowerCase();
        var found = false;
        (h.ports || []).forEach(function(p) {
          if ((p.service || '').toLowerCase().indexOf(sf) >= 0) found = true;
        });
        if (!found) return;
      }
      if (state.riskThreshold > 0 && h.risk_score < state.riskThreshold) return;
      h._vlanId = v.id;
      h._vlanName = v.name;
      hosts.push(h);
    });
  });
  return hosts;
}

// ─── Risk Color ───────────────────────────────────────────────
function riskColor(score) {
  if (score >= 750) return '#b71c1c';
  if (score >= 500) return '#e65100';
  if (score >= 250) return '#f57f17';
  return '#1b5e20';
}
function riskClass(score) {
  if (score >= 750) return 'risk-critical';
  if (score >= 500) return 'risk-high';
  if (score >= 250) return 'risk-medium';
  return 'risk-low';
}
function riskLabel(score) {
  if (score >= 750) return 'CRITICAL';
  if (score >= 500) return 'HIGH';
  if (score >= 250) return 'MEDIUM';
  return 'LOW';
}

// ─── D3 Force Graph ───────────────────────────────────────────
function renderGraph(vlanId) {
  var container = document.getElementById('graph-container');
  container.innerHTML = '';

  var hosts = filteredHosts(vlanId);
  if (hosts.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:60px;color:#666;font-size:16px">No hosts match current filters</div>';
    return;
  }

  var width = container.clientWidth;
  var height = container.clientHeight;

  // ── Adaptive spacing based on host count ──
  // More hosts = more repulsion and larger collision to prevent overlap.
  // Fewer hosts (filtered VLAN view) = spread them wide to use all space.
  var n = hosts.length;
  var isSingleVLAN = !!vlanId;
  var chargeStrength = isSingleVLAN ? -600 : Math.max(-500, -50 * Math.sqrt(n));
  var collisionPad = isSingleVLAN ? 35 : Math.max(18, 30 - n * 0.2);
  var linkDist = isSingleVLAN ? 160 : Math.max(80, 120 - n * 0.3);
  var labelOffset = 16;

  // Build nodes
  var nodes = hosts.map(function(h, i) {
    return {
      id: h.ip,
      host: h,
      radius: Math.max(8, 6 + (h.risk_score / 1000) * 12),
      isGateway: (h.device_type === 'router' || h.device_type === 'gateway' || h.device_type === 'firewall'),
      isLocal: h.is_local
    };
  });

  // Build node index
  var nodeMap = {};
  nodes.forEach(function(n) { nodeMap[n.id] = n; });

  // Build links from CONNECTIONS filtered to visible nodes.
  // Hide same_vlan edges by default; users can toggle them on via the checkbox.
  var showSameVlan = state.showSameVlanEdges;
  var links = [];
  (CONNECTIONS || []).forEach(function(c) {
    if (!nodeMap[c.source] || !nodeMap[c.target]) return;
    if (c.type === 'same_vlan' && !showSameVlan) return;
    links.push({ source: c.source, target: c.target, type: c.type, label: c.label });
  });


  // VLAN color mapping
  var vlanColorMap = {};
  var vi = 0;
  var vlansInGraph = {};
  nodes.forEach(function(n) { vlansInGraph[n.host._vlanId] = true; });
  var uniqueVLANs = Object.keys(vlansInGraph).sort();
  uniqueVLANs.forEach(function(vid) {
    vlanColorMap[vid] = VLAN_COLORS[vi % VLAN_COLORS.length];
    vi++;
  });

  // Create SVG with expanded viewport so nodes have room to spread
  var svgW = isSingleVLAN ? Math.max(width, n * 80) : width;
  var svgH = isSingleVLAN ? Math.max(height, n * 60) : height;
  var svg = d3.select('#graph-container').append('svg')
    .attr('width', svgW)
    .attr('height', svgH);

  var g = svg.append('g');

  // Zoom
  var zoom = d3.zoom()
    .scaleExtent([0.05, 8])
    .on('zoom', function(event) {
      g.attr('transform', event.transform);
    });
  svg.call(zoom);

  // Auto-center: called once after simulation cools
  var centered = false;
  function centerGraph() {
    if (centered) return;
    centered = true;
    var bounds = g.node().getBBox();
    if (bounds.width === 0 || bounds.height === 0) return;
    var fullWidth = container.clientWidth;
    var fullHeight = container.clientHeight;
    var midX = bounds.x + bounds.width / 2;
    var midY = bounds.y + bounds.height / 2;
    var scale = 0.9 / Math.max(bounds.width / fullWidth, bounds.height / fullHeight);
    scale = Math.min(scale, 3);
    var translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];
    svg.transition().duration(600).call(
      zoom.transform,
      d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
    );
  }

  // VLAN hull groups (drawn first, behind everything)
  var hullGroup = g.append('g').attr('class', 'hulls');

  // Draw hulls function
  function drawHulls() {
    hullGroup.selectAll('*').remove();
    var vlanNodes = {};
    nodes.forEach(function(n) {
      if (!vlanNodes[n.host._vlanId]) vlanNodes[n.host._vlanId] = [];
      vlanNodes[n.host._vlanId].push([n.x, n.y]);
    });
    Object.keys(vlanNodes).forEach(function(vid) {
      var pts = vlanNodes[vid];
      var color = vlanColorMap[vid] || '#333';
      if (pts.length < 2) {
        hullGroup.append('circle')
          .attr('cx', pts[0][0])
          .attr('cy', pts[0][1])
          .attr('r', 40)
          .attr('fill', color)
          .attr('class', 'vlan-hull');
        // Label
        var nm = nodes.find(function(n){ return n.host._vlanId === vid; });
        hullGroup.append('text')
          .attr('x', pts[0][0])
          .attr('y', pts[0][1] - 50)
          .attr('text-anchor', 'middle')
          .attr('class', 'vlan-label')
          .text(nm ? nm.host._vlanName : 'VLAN ' + vid);
        return;
      }
      var hull = d3.polygonHull(pts);
      if (!hull) return;
      // Expand hull to give nodes room
      var cx = 0, cy = 0;
      hull.forEach(function(p) { cx += p[0]; cy += p[1]; });
      cx /= hull.length; cy /= hull.length;
      var expandFactor = 1 + 50 / Math.max(
        Math.sqrt(hull.reduce(function(s,p){ return s + (p[0]-cx)*(p[0]-cx) + (p[1]-cy)*(p[1]-cy); }, 0) / hull.length),
        1
      );
      var expanded = hull.map(function(p) {
        return [cx + (p[0] - cx) * expandFactor, cy + (p[1] - cy) * expandFactor];
      });
      hullGroup.append('path')
        .attr('d', 'M' + expanded.join('L') + 'Z')
        .attr('fill', color)
        .attr('stroke', color)
        .attr('class', 'vlan-hull');
      // VLAN label above the hull
      var top = expanded.reduce(function(m, p) { return p[1] < m[1] ? p : m; }, expanded[0]);
      var nm = nodes.find(function(n){ return n.host._vlanId === vid; });
      hullGroup.append('text')
        .attr('x', cx)
        .attr('y', top[1] - 8)
        .attr('text-anchor', 'middle')
        .attr('class', 'vlan-label')
        .text(nm ? nm.host._vlanName : 'VLAN ' + vid);
    });
  }

  // Links
  var link = g.append('g').selectAll('line')
    .data(links)
    .enter().append('line')
    .attr('class', function(d) { return 'link ' + d.type; })
    .attr('stroke', function(d) {
      if (d.type === 'gateway') return '#e94560';
      if (d.type === 'physical') return '#64B5F6';
      return '#444';
    })
    .attr('stroke-width', function(d) {
      if (d.type === 'gateway') return 2;
      if (d.type === 'physical') return 2;
      return 1;
    });

  // Physical link interface labels
  var linkLabels = g.append('g').selectAll('text')
    .data(links.filter(function(d) { return d.type === 'physical' && d.label; }))
    .enter().append('text')
    .attr('class', 'link-label')
    .attr('text-anchor', 'middle')
    .text(function(d) { return d.label; });

  // Nodes
  var node = g.append('g').selectAll('g')
    .data(nodes)
    .enter().append('g')
    .attr('class', function(d) {
      var cls = 'node';
      if (d.isGateway) cls += ' gateway';
      if (d.isLocal) cls += ' local';
      else cls += ' remote';
      return cls;
    })
    .call(d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended));

  // Node circle
  node.append('circle')
    .attr('r', function(d) { return d.radius; })
    .attr('fill', function(d) {
      var cat = d.host.category;
      var base = CAT_COLORS[cat] || CAT_COLORS.unknown;
      if (d.host.risk_score > 0) {
        var rc = riskColor(d.host.risk_score);
        return d3.interpolateRgb(base, rc)(Math.min(d.host.risk_score / 1000, 1) * 0.6);
      }
      return base;
    })
    .attr('stroke', function(d) {
      return d.isGateway ? '#fff' : (CAT_COLORS[d.host.category] || CAT_COLORS.unknown);
    })
    .attr('stroke-width', function(d) { return d.isGateway ? 3 : 2; });

  // Compliance ring — coloured outer ring on network device nodes with compliance data
  var COMPLIANCE_RING_COLORS = { critical: '#b71c1c', warning: '#FF9800', ok: '#4CAF50' };
  node.filter(function(d) {
    return d.host.compliance_severity && COMPLIANCE_RING_COLORS[d.host.compliance_severity];
  }).append('circle')
    .attr('class', 'compliance-ring')
    .attr('r', function(d) { return d.radius + 5; })
    .attr('stroke', function(d) { return COMPLIANCE_RING_COLORS[d.host.compliance_severity]; })
    .attr('stroke-width', 3);

  // Gateway indicator
  node.filter(function(d){ return d.isGateway; })
    .append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '0.35em')
    .attr('fill', '#fff')
    .attr('font-size', '9px')
    .attr('style', 'pointer-events:none')
    .text('G');

  // Node label (hostname or IP)
  node.append('text')
    .attr('class', 'node-label')
    .attr('dy', function(d) { return d.radius + labelOffset; })
    .text(function(d) {
      var name = d.host.hostname || d.host.ip;
      return name.length > 20 ? name.substring(0, 17) + '...' : name;
    });

  // Sub-type label beneath hostname
  node.filter(function(d) { return !!hostSubtype(d.host); })
    .append('text')
    .attr('class', 'node-sub')
    .attr('dy', function(d) { return d.radius + labelOffset + 11; })
    .text(function(d) { return hostSubtype(d.host); });

  // Click handler
  node.on('click', function(event, d) {
    event.stopPropagation();
    showDetail(d.host);
  });

  // Hover highlight
  node.on('mouseenter', function(event, d) {
    node.classed('dimmed', function(n) { return n !== d; });
    link.attr('stroke-opacity', function(l) {
      return (l.source.id === d.id || l.target.id === d.id) ? 0.8 : 0.1;
    });
  }).on('mouseleave', function() {
    node.classed('dimmed', false);
    link.attr('stroke-opacity', 0.4);
  });

  // ── Force simulation with adaptive parameters ──
  if (state.simulation) state.simulation.stop();

  // In the overview the VLAN clustering forces handle positioning; the global
  // center pull is kept very weak so it doesn't fight cluster separation.
  var centerStrength = isSingleVLAN ? 0.05 : 0.01;

  state.simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(function(d) { return d.id; })
      .distance(linkDist)
      // Physical edges cross VLAN boundaries. They are resolved by forceLink so
      // source/target become node objects (needed for rendering), but strength=0
      // means they exert no spring force and cannot pull clusters together.
      .strength(function(l) { return (l.type === 'physical' && !isSingleVLAN) ? 0 : 0.7; }))
    .force('charge', d3.forceManyBody().strength(chargeStrength))
    .force('center', d3.forceCenter(svgW / 2, svgH / 2))
    .force('collision', d3.forceCollide().radius(function(d) { return d.radius + collisionPad; }))
    .force('x', d3.forceX(svgW / 2).strength(centerStrength))
    .force('y', d3.forceY(svgH / 2).strength(centerStrength));

  // VLAN clustering force (only for multi-VLAN overview).
  // Strength 0.3 keeps clusters well-separated; higher values produce a more
  // rigid radial layout at the cost of less organic node spreading within a VLAN.
  if (uniqueVLANs.length > 1 && !isSingleVLAN) {
    var vlanCenters = {};
    // Cluster radius: ensure at least 220px of arc between adjacent cluster centres
    // so VLAN hulls cannot overlap regardless of node count. Also keep a minimum
    // fraction of the viewport so small networks still spread out.
    var minArcSep = 220;
    var angularSep = uniqueVLANs.length > 1 ? (2 * Math.PI / uniqueVLANs.length) : Math.PI;
    var minRByArc = minArcSep / (2 * Math.sin(angularSep / 2));
    var minRByViewport = Math.min(svgW, svgH) * 0.35;
    var clusterR = Math.max(minRByArc, minRByViewport);
    uniqueVLANs.forEach(function(vid, i) {
      var angle = (2 * Math.PI * i) / uniqueVLANs.length - Math.PI / 2;
      vlanCenters[vid] = { x: svgW / 2 + clusterR * Math.cos(angle), y: svgH / 2 + clusterR * Math.sin(angle) };
    });
    state.simulation
      .force('vlanX', d3.forceX(function(d) {
        return vlanCenters[d.host._vlanId] ? vlanCenters[d.host._vlanId].x : svgW / 2;
      }).strength(0.5))
      .force('vlanY', d3.forceY(function(d) {
        return vlanCenters[d.host._vlanId] ? vlanCenters[d.host._vlanId].y : svgH / 2;
      }).strength(0.5));
  }

  state.simulation.on('tick', function() {
    link
      .attr('x1', function(d) { return d.source.x; })
      .attr('y1', function(d) { return d.source.y; })
      .attr('x2', function(d) { return d.target.x; })
      .attr('y2', function(d) { return d.target.y; });
    linkLabels
      .attr('x', function(d) { return (d.source.x + d.target.x) / 2; })
      .attr('y', function(d) { return (d.source.y + d.target.y) / 2 - 4; });
    node.attr('transform', function(d) { return 'translate(' + d.x + ',' + d.y + ')'; });
    drawHulls();
  });

  // Auto-center after simulation cools. Use alphaDecay to detect convergence
  // rather than 'end' event, which is unreliable after drag interactions.
  setTimeout(function() {
    if (state.simulation && state.simulation.alpha() < 0.05) centerGraph();
  }, 2000);
  setTimeout(function() { centerGraph(); }, 4000);

  // Drag functions
  function dragstarted(event, d) {
    if (!event.active) state.simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }
  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }
  function dragended(event, d) {
    if (!event.active) state.simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }
}

// ─── Detail Panel ─────────────────────────────────────────────
function showDetail(h) {
  state.selectedHost = h;
  var panel = document.getElementById('detail-panel');
  var content = document.getElementById('detail-content');
  var html = '';

  // Title + IP
  html += '<h2>' + escHtml(h.hostname || h.ip) + '</h2>';
  html += '<div class="field"><span class="label">IP:</span> <span class="value">' + escHtml(h.ip) + '</span></div>';

  // Risk badge
  if (h.risk_score > 0) {
    html += '<div style="margin:8px 0"><span class="risk-badge ' + riskClass(h.risk_score) + '">Risk: ' + h.risk_score + ' (' + riskLabel(h.risk_score) + ')</span></div>';
    var rd = h.risk_details || {};
    var total = h.risk_score || 1;
    var vulnPct = ((rd.vulnerability_score || 0) / total * 100);
    var sslPct = ((rd.ssl_issues || 0) / total * 100);
    var svcPct = ((rd.service_exposure || 0) / total * 100);
    var portPct = ((rd.open_port_score || 0) / total * 100);
    html += '<div class="risk-bar">';
    html += '<div class="risk-bar-segment" style="width:' + vulnPct + '%;background:#b71c1c" title="Vulnerabilities: ' + (rd.vulnerability_score || 0) + '"></div>';
    html += '<div class="risk-bar-segment" style="width:' + sslPct + '%;background:#e65100" title="SSL Issues: ' + (rd.ssl_issues || 0) + '"></div>';
    html += '<div class="risk-bar-segment" style="width:' + svcPct + '%;background:#f57f17" title="Service Exposure: ' + (rd.service_exposure || 0) + '"></div>';
    html += '<div class="risk-bar-segment" style="width:' + portPct + '%;background:#1b5e20" title="Open Ports: ' + (rd.open_port_score || 0) + '"></div>';
    html += '</div>';
    html += '<div style="font-size:10px;color:#666;margin-bottom:4px">Vuln ' + (rd.vulnerability_score||0) + ' | SSL ' + (rd.ssl_issues||0) + ' | Exposure ' + (rd.service_exposure||0) + ' | Ports ' + (rd.open_port_score||0) + '</div>';
  }

  // Category + sub-type
  var catLabel = CAT_LABELS[h.category] || h.category;
  var sub = hostSubtype(h);
  if (sub) catLabel += ' \u203A ' + sub;
  html += '<div class="field"><span class="label">Category:</span> <span class="value">' + catLabel + '</span></div>';

  // Metadata
  if (h.mac) html += '<div class="field"><span class="label">MAC:</span> <span class="value">' + escHtml(h.mac) + '</span></div>';
  if (h.os) html += '<div class="field"><span class="label">OS:</span> <span class="value">' + escHtml(h.os) + '</span></div>';
  if (h.vendor) html += '<div class="field"><span class="label">Vendor:</span> <span class="value">' + escHtml(h.vendor) + '</span></div>';
  if (h.vlan_id) html += '<div class="field"><span class="label">VLAN:</span> <span class="value">' + escHtml(h.vlan_name || h.vlan_id) + '</span></div>';
  if (h.device_type) html += '<div class="field"><span class="label">Device:</span> <span class="value">' + escHtml(h.device_type) + '</span></div>';
  html += '<div class="field"><span class="label">Segment:</span> <span class="value">' + (h.is_local ? 'Local (same segment)' : 'Remote (behind gateway)') + '</span></div>';

  // Open Ports
  var openPorts = (h.ports || []).filter(function(p) { return p.state === 'open'; });
  if (openPorts.length > 0) {
    html += '<h3>Open Ports (' + openPorts.length + ')</h3>';
    html += '<table class="ports-table"><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr>';
    openPorts.forEach(function(p) {
      html += '<tr><td>' + p.number + '</td><td>' + p.protocol + '</td><td>' + escHtml(p.service || '-') + '</td><td>' + escHtml(p.version || '') + '</td></tr>';
    });
    html += '</table>';
  }

  // Vulnerabilities
  var vulns = h.vulnerabilities || [];
  if (vulns.length > 0) {
    html += '<h3>Vulnerabilities (' + vulns.length + ')</h3>';
    vulns.forEach(function(v) {
      var sev = (v.severity || 'info').toLowerCase();
      html += '<div class="vuln-item vuln-' + sev + '">';
      html += '<span class="vuln-severity" style="color:' + (SEV_COLORS[sev] || '#888') + '">' + escHtml(sev) + '</span>';
      if (v.cve) html += '<span style="color:#64B5F6">' + escHtml(v.cve) + '</span> ';
      html += escHtml(v.title || 'Unknown');
      if (v.port) html += ' <span style="color:#666">(port ' + v.port + ')</span>';
      html += '</div>';
    });
  }

  // Recommendations
  var recs = h.recommendations || [];
  if (recs.length > 0) {
    html += '<h3>Recommendations</h3>';
    recs.forEach(function(r) {
      html += '<div class="rec-item">' + escHtml(r) + '</div>';
    });
  }

  // Security Compliance (network devices only — populated from gathered configs)
  var compFindings = h.compliance_findings || [];
  if (compFindings.length > 0) {
    var sevColor = { critical: '#b71c1c', warning: '#FF9800', ok: '#4CAF50' };
    var sevBadge = { critical: 'CRITICAL', warning: 'WARN', ok: 'PASS' };
    html += '<div class="compliance-section"><h3>Security Compliance</h3>';
    compFindings.forEach(function(f) {
      var sev = (f.severity || 'ok').toLowerCase();
      var icon = (sev === 'ok') ? '✓' : '✗';
      var color = sevColor[sev] || '#888';
      html += '<div class="compliance-item" style="color:' + color + '">';
      html += '<span style="margin-right:6px">' + icon + '</span>';
      html += '<span>' + escHtml(f.check) + '</span>';
      if (f.detail && sev !== 'ok') {
        html += '<div style="font-size:11px;color:#888;margin-left:20px">' + escHtml(f.detail) + '</div>';
      }
      html += '</div>';
    });
    html += '</div>';
  }

  content.innerHTML = html;
  panel.classList.add('open');
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
  state.selectedHost = null;
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Tab Switching ────────────────────────────────────────────
function switchTab(tabId) {
  state.currentTab = tabId;
  if (state.simulation) { state.simulation.stop(); state.simulation = null; }

  var tabs = document.querySelectorAll('.tab');
  tabs.forEach(function(t) { t.classList.remove('active'); });
  tabs.forEach(function(t) {
    if (t.dataset.tabId === tabId) t.classList.add('active');
  });

  closeDetail();
  renderGraph(tabId === 'overview' ? null : tabId);
}

// ─── Toolbar ──────────────────────────────────────────────────
function buildToolbar() {
  var toolbar = document.getElementById('toolbar');
  toolbar.innerHTML = '';

  var search = document.createElement('input');
  search.type = 'text';
  search.placeholder = 'Search IP, hostname, vendor...';
  search.value = state.searchText;
  search.oninput = function() { state.searchText = search.value; renderGraph(state.currentTab === 'overview' ? null : state.currentTab); };
  toolbar.appendChild(search);

  var svcSearch = document.createElement('input');
  svcSearch.type = 'text';
  svcSearch.placeholder = 'Filter by service...';
  svcSearch.value = state.serviceFilter;
  svcSearch.oninput = function() { state.serviceFilter = svcSearch.value; renderGraph(state.currentTab === 'overview' ? null : state.currentTab); };
  toolbar.appendChild(svcSearch);

  // Risk threshold
  var riskLabel = document.createElement('label');
  riskLabel.textContent = 'Min Risk: ';
  var riskSel = document.createElement('select');
  [{v:0,l:'Any'},{v:100,l:'100+'},{v:250,l:'250+'},{v:500,l:'500+'},{v:750,l:'750+'}].forEach(function(o) {
    var opt = document.createElement('option');
    opt.value = o.v;
    opt.textContent = o.l;
    if (state.riskThreshold === o.v) opt.selected = true;
    riskSel.appendChild(opt);
  });
  riskSel.onchange = function() { state.riskThreshold = parseInt(riskSel.value) || 0; renderGraph(state.currentTab === 'overview' ? null : state.currentTab); };
  riskLabel.appendChild(riskSel);
  toolbar.appendChild(riskLabel);

  // Same-VLAN edge toggle
  var edgeLbl = document.createElement('label');
  var edgeCb = document.createElement('input');
  edgeCb.type = 'checkbox';
  edgeCb.checked = state.showSameVlanEdges;
  edgeCb.onchange = function() {
    state.showSameVlanEdges = edgeCb.checked;
    renderGraph(null);
  };
  edgeLbl.appendChild(edgeCb);
  edgeLbl.appendChild(document.createTextNode(' Show connections'));
  toolbar.appendChild(edgeLbl);

  // Category filters (only the 3 real categories + unknown)
  ['network_device', 'windows', 'linux', 'unknown'].forEach(function(cat) {
    var lbl = document.createElement('label');
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = state.filters[cat];
    cb.onchange = function() { state.filters[cat] = cb.checked; renderGraph(state.currentTab === 'overview' ? null : state.currentTab); };
    var swatch = document.createElement('span');
    swatch.style.cssText = 'display:inline-block;width:10px;height:10px;border-radius:2px;background:' + CAT_COLORS[cat];
    lbl.appendChild(cb);
    lbl.appendChild(swatch);
    lbl.appendChild(document.createTextNode(' ' + (CAT_LABELS[cat] || cat)));
    toolbar.appendChild(lbl);
  });
}

// ─── Legend ────────────────────────────────────────────────────
function buildLegend() {
  var legend = document.getElementById('legend');
  legend.innerHTML = '';

  // Category colors
  ['network_device', 'windows', 'linux'].forEach(function(cat) {
    var item = document.createElement('div');
    item.className = 'legend-item';
    var c = document.createElement('span');
    c.className = 'legend-color';
    c.style.background = CAT_COLORS[cat];
    item.appendChild(c);
    item.appendChild(document.createTextNode(CAT_LABELS[cat]));
    legend.appendChild(item);
  });

  // Risk gradient
  var riskItem = document.createElement('div');
  riskItem.className = 'legend-item';
  var riskGrad = document.createElement('span');
  riskGrad.style.cssText = 'display:inline-block;width:60px;height:12px;border-radius:3px;background:linear-gradient(to right,#1b5e20,#f57f17,#e65100,#b71c1c)';
  riskItem.appendChild(riskGrad);
  riskItem.appendChild(document.createTextNode(' Risk (0 \u2192 1000)'));
  legend.appendChild(riskItem);

  // Segment types
  var localItem = document.createElement('div');
  localItem.className = 'legend-item';
  var localBox = document.createElement('span');
  localBox.className = 'legend-color';
  localBox.style.cssText = 'border:2px solid #aaa;background:transparent;border-radius:50%';
  localItem.appendChild(localBox);
  localItem.appendChild(document.createTextNode(' Local (same segment)'));
  legend.appendChild(localItem);

  var remoteItem = document.createElement('div');
  remoteItem.className = 'legend-item';
  var remoteBox = document.createElement('span');
  remoteBox.className = 'legend-color';
  remoteBox.style.cssText = 'border:2px dashed #aaa;background:transparent;border-radius:50%';
  remoteItem.appendChild(remoteBox);
  remoteItem.appendChild(document.createTextNode(' Remote (behind gateway)'));
  legend.appendChild(remoteItem);

  // Gateway
  var gwItem = document.createElement('div');
  gwItem.className = 'legend-item';
  var gwBox = document.createElement('span');
  gwBox.className = 'legend-color';
  gwBox.style.cssText = 'border:3px solid #fff;background:#e94560;border-radius:50%;font-size:7px;color:#fff;text-align:center;line-height:12px';
  gwBox.textContent = 'G';
  gwItem.appendChild(gwBox);
  gwItem.appendChild(document.createTextNode(' Gateway/Router'));
  legend.appendChild(gwItem);

  // Link types
  var linkItem = document.createElement('div');
  linkItem.className = 'legend-item';
  var linkLine = document.createElement('span');
  linkLine.style.cssText = 'display:inline-block;width:24px;height:0;border-top:2px dashed #e94560';
  linkItem.appendChild(linkLine);
  linkItem.appendChild(document.createTextNode(' Gateway link'));
  legend.appendChild(linkItem);

  var physItem = document.createElement('div');
  physItem.className = 'legend-item';
  var physLine = document.createElement('span');
  physLine.style.cssText = 'display:inline-block;width:24px;height:0;border-top:2px solid #64B5F6';
  physItem.appendChild(physLine);
  physItem.appendChild(document.createTextNode(' Physical port link'));
  legend.appendChild(physItem);

  // Compliance ring indicators
  [['critical','#b71c1c','Critical issues'],['warning','#FF9800','Warnings'],['ok','#4CAF50','Compliant']].forEach(function(row) {
    var item = document.createElement('div');
    item.className = 'legend-item';
    var ring = document.createElement('span');
    ring.style.cssText = 'display:inline-block;width:12px;height:12px;border-radius:50%;border:3px solid ' + row[1] + ';background:transparent';
    item.appendChild(ring);
    item.appendChild(document.createTextNode(' Compliance: ' + row[2]));
    legend.appendChild(item);
  });
}

// ─── Init ─────────────────────────────────────────────────────
function init() {
  var tabs = document.getElementById('tab-bar');

  var overviewTab = document.createElement('button');
  overviewTab.className = 'tab active';
  overviewTab.dataset.tabId = 'overview';
  var totalHosts = VLANS.reduce(function(s, v) { return s + v.hosts.length; }, 0);
  overviewTab.innerHTML = 'Overview <span class="badge">' + totalHosts + '</span>';
  overviewTab.onclick = function() { switchTab('overview'); };
  tabs.appendChild(overviewTab);
  state.currentTab = 'overview';

  VLANS.forEach(function(v) {
    var tab = document.createElement('button');
    tab.className = 'tab';
    tab.dataset.tabId = v.id;
    tab.innerHTML = escHtml(v.name) + ' <span class="badge">' + v.hosts.length + '</span>';
    if (v.avg_risk > 0) {
      tab.innerHTML += ' <span style="font-size:10px;color:' + riskColor(v.avg_risk) + '">\u26A0 ' + v.avg_risk + '</span>';
    }
    tab.onclick = function() { switchTab(v.id); };
    tabs.appendChild(tab);
  });

  document.getElementById('stats').textContent = VLANS.length + ' VLANs / ' + totalHosts + ' hosts';

  buildToolbar();
  buildLegend();
  renderGraph(null);
}

init();
`
