package correlation

import _ "embed"

// topologyD3 contains the minified D3.js v7 library for the topology viewer.
//
//go:embed embedded/d3.v7.min.js
var topologyD3 string
