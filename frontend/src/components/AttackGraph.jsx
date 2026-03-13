import { useEffect, useRef, useState } from "react"
import cytoscape from "cytoscape"
import dagre from "cytoscape-dagre"
import { getAttackGraph } from "../api/client"

cytoscape.use(dagre)

const SEVERITY_COLORS = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#4ade80",
}

function nodeColor(data) {
  if (data.id === "internet") return "#7fbfff"
  return SEVERITY_COLORS[data.severity] ?? "#7fbfff"
}

export default function AttackGraph() {
  const cyRef = useRef(null)
  const cyInstance = useRef(null)

  const [graphData, setGraphData] = useState(null)
  const [started, setStarted] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAttackGraph()
      .then((data) => {
        setGraphData(data)

        cyInstance.current = cytoscape({
          container: cyRef.current,
          elements: [],
          style: [
            {
              selector: "node",
              style: {
                label: "data(label)",
                "background-color": "#7fbfff",
                color: "#fff",
                "text-valign": "bottom",
                "text-halign": "center",
                "text-margin-y": 8,
                width: 0,
                height: 0,
                "font-family": "Orbitron, sans-serif",
                "font-size": "12px",
                "font-weight": "500",
                "text-outline-color": "#000",
                "text-outline-width": 2,
              },
            },
            {
              selector: "edge",
              style: {
                width: 2,
                label: "data(type)",
                "font-size": "10px",
                color: "#a0aec0",
                "text-rotation": "autorotate",
                "text-margin-y": -10,
                "line-color": "#4a5568",
                "target-arrow-color": "#4a5568",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                opacity: 0,
              },
            },
            {
              selector: "node[id='internet']",
              style: {
                shape: "star",
                "background-color": "#7fbfff",
              }
            }
          ],
          layout: {
            name: "dagre",
            rankDir: "LR",
            nodeSep: 100,
            edgeSep: 60,
            rankSep: 150,
          },
        })
      })
      .catch((err) => {
        console.error("Attack Graph failed to load:", err)
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  function buildGraph() {
    if (!graphData || started) return
    setStarted(true)

    const cy = cyInstance.current
    const { nodes, edges } = graphData

    let nodeIndex = 0

    function addNextNode() {
      if (nodeIndex < nodes.length) {
        const node = cy.add(nodes[nodeIndex])
        const color = nodeColor(nodes[nodeIndex].data)

        node.style("background-color", color)
        node.animate({ style: { width: 45, height: 45 } }, { duration: 600 })

        nodeIndex++
        setTimeout(addNextNode, 400)
      } else {
        addEdges()
      }
    }

    let edgeIndex = 0

    function addEdges() {
      if (edgeIndex < edges.length) {
        const edge = cy.add(edges[edgeIndex])

        // Highlight critical paths
        if (edges[edgeIndex].data.source !== "internet") {
          edge.style({
            "line-color": "#7fbfff",
            "target-arrow-color": "#7fbfff",
            "width": 3
          })
        }

        edge.animate({ style: { opacity: 1 } }, { duration: 500 })

        // Reflow layout as we add edges
        cy.layout({
          name: "dagre",
          rankDir: "LR",
          animate: true,
          animationDuration: 500,
          spacingFactor: 1.2
        }).run()

        edgeIndex++
        setTimeout(addEdges, 400)
      } else {
        pulseEdges()
      }
    }

    function pulseEdges() {
      const allEdges = cy.edges()
      setInterval(() => {
        allEdges.animate({ style: { width: 4 } }, { duration: 300 })
        setTimeout(() => {
          allEdges.animate({ style: { width: 2 } }, { duration: 300 })
        }, 300)
      }, 2000)
    }

    addNextNode()
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-4 metal-blue hud-title">
        ATTACK PATH VISUALIZATION
      </h2>

      {/* Legend */}
      <div className="flex gap-4 mb-4 text-xs hud-title">
        {Object.entries(SEVERITY_COLORS).map(([label, color]) => (
          <span key={label} className="flex items-center gap-1">
            <span
              className="inline-block w-3 h-3 rounded-full"
              style={{ background: color }}
            />
            {label}
          </span>
        ))}
        <span className="flex items-center gap-1">
          <span className="inline-block w-3 h-3 rounded-full bg-blue-300" />
          INTERNET
        </span>
      </div>

      <button
        onClick={buildGraph}
        disabled={loading || started}
        className="mb-6 px-5 py-2 border border-blue-300 text-blue-300 rounded-md hover:bg-blue-300 hover:text-black transition duration-300 hud-title text-sm disabled:opacity-50"
      >
        {loading ? "LOADING DATA..." : started ? "GRAPH BUILT" : "BUILD GRAPH"}
      </button>

      <div
        ref={cyRef}
        className="bg-black/30 border border-gray-700 rounded-lg"
        style={{ height: "520px" }}
      />
    </div>
  )
}