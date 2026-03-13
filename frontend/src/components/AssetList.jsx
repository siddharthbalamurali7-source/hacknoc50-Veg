import { useEffect, useState } from "react"
import { getAssets, getAllScores } from "../api/client"

const SEVERITY_STYLES = {
  CRITICAL: "text-red-400 border-red-400",
  HIGH: "text-orange-400 border-orange-400",
  MEDIUM: "text-yellow-400 border-yellow-400",
  LOW: "text-green-400 border-green-400",
}

export default function AssetList() {
  const [assets, setAssets] = useState([])
  const [scoreMap, setScoreMap] = useState({})
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    async function load() {
      try {
        const [assetData, scoreData] = await Promise.all([getAssets(), getAllScores()])

        // Ensure data is expected array type
        const safeAssets = Array.isArray(assetData) ? assetData : []
        const safeScores = Array.isArray(scoreData) ? scoreData : []

        setAssets(safeAssets)

        const map = {}
        safeScores.forEach((s) => {
          if (s && s.asset_id) map[s.asset_id] = s
        })
        setScoreMap(map)
      } catch (err) {
        console.error("Failed to load assets:", err)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-40">
        <p className="metal-blue hud-title text-sm animate-pulse">SCANNING...</p>
      </div>
    )
  }

  return (
    <div className="slide-in">
      <h2 className="text-2xl font-bold mb-6 metal-blue hud-title">
        NETWORK ASSETS
      </h2>

      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-gray-700 hud-title metal-blue text-xs">
              <th className="pb-3 pr-4">HOSTNAME</th>
              <th className="pb-3 pr-4">IP ADDRESS</th>
              <th className="pb-3 pr-4">OS</th>
              <th className="pb-3 pr-4">RISK SCORE</th>
              <th className="pb-3 pr-4">SEVERITY</th>
              <th className="pb-3 pr-4">OPEN PORTS</th>
              <th className="pb-3 pr-4">CRITICALITY</th>
              <th className="pb-3">EXPOSED</th>
            </tr>
          </thead>

          <tbody>
            {assets.map((a) => {
              const score = scoreMap[a.id]
              const sevStyle =
                SEVERITY_STYLES[a.severity_label] ?? "text-gray-400 border-gray-400"
              const isOpen = expanded === a.id

              return (
                <>
                  <tr
                    key={a.id}
                    className="border-b border-gray-800 hover:bg-gray-800/50 transition cursor-pointer"
                    onClick={() => setExpanded(isOpen ? null : a.id)}
                  >
                    <td className="py-3 pr-4 font-medium">{a.hostname ?? "—"}</td>
                    <td className="py-3 pr-4 text-gray-400">{a.ip_address}</td>
                    <td className="py-3 pr-4 text-gray-400">{a.os ?? "Unknown"}</td>
                    <td className={`py-3 pr-4 hud-title font-bold ${sevStyle.split(" ")[0]}`}>
                      {a.risk_score ?? "—"}
                    </td>
                    <td className="py-3 pr-4">
                      <span
                        className={`border px-2 py-0.5 rounded text-xs hud-title ${sevStyle}`}
                      >
                        {a.severity_label ?? "—"}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-gray-300">
                      {a.open_ports?.join(", ") || "—"}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex gap-0.5">
                        {[1, 2, 3, 4, 5].map((n) => (
                          <div
                            key={n}
                            className={`w-2 h-2 rounded-sm ${n <= (a.criticality ?? 0)
                                ? "bg-blue-400"
                                : "bg-gray-700"
                              }`}
                          />
                        ))}
                      </div>
                    </td>
                    <td className="py-3">
                      <span
                        className={`text-xs hud-title ${a.internet_exposed ? "text-red-400" : "text-gray-500"
                          }`}
                      >
                        {a.internet_exposed ? "YES" : "NO"}
                      </span>
                    </td>
                  </tr>

                  {/* Expanded detail row */}
                  {isOpen && score && (
                    <tr key={`${a.id}-detail`} className="bg-gray-900/60">
                      <td colSpan={8} className="px-4 py-4">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                          {/* Score breakdown */}
                          <div>
                            <p className="metal-blue hud-title mb-2">SCORE BREAKDOWN</p>
                            {Object.entries(score.breakdown ?? {}).map(([k, v]) => (
                              <div key={k} className="flex justify-between text-gray-400 mb-1">
                                <span className="capitalize">{k}</span>
                                <span className="text-white">{v}</span>
                              </div>
                            ))}
                          </div>

                          {/* Top CVEs */}
                          <div>
                            <p className="metal-blue hud-title mb-2">TOP CVEs</p>
                            {score.top_cves?.length ? (
                              score.top_cves.map((cve) => (
                                <p key={cve} className="text-red-300 mb-1">{cve}</p>
                              ))
                            ) : (
                              <p className="text-gray-500">None detected</p>
                            )}
                          </div>

                          {/* Software */}
                          <div>
                            <p className="metal-blue hud-title mb-2">SOFTWARE</p>
                            {a.software_list?.map((sw) => (
                              <p key={sw.name} className="text-gray-400 mb-1">
                                {sw.name}{" "}
                                <span className="text-gray-600">v{sw.version}</span>
                              </p>
                            ))}
                          </div>

                          {/* Timestamps */}
                          <div>
                            <p className="metal-blue hud-title mb-2">TIMESTAMPS</p>
                            <p className="text-gray-500 mb-1">
                              Scanned:{" "}
                              <span className="text-gray-300">
                                {a.last_scanned
                                  ? new Date(a.last_scanned).toLocaleDateString()
                                  : "—"}
                              </span>
                            </p>
                            <p className="text-gray-500">
                              Scored:{" "}
                              <span className="text-gray-300">
                                {a.last_scored
                                  ? new Date(a.last_scored).toLocaleDateString()
                                  : "—"}
                              </span>
                            </p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}