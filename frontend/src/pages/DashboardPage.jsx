import { useEffect, useState } from "react"
import { getScoreSummary, recalculateAllScores, seedAssets, seedScenarios } from "../api/client"

const SEVERITY_COLOR = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-green-400",
}

export default function DashboardPage() {
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [hover, setHover] = useState(null)
  const [seeding, setSeeding] = useState(false)

  useEffect(() => {
    getScoreSummary()
      .then((data) => {
        setSummary(data)
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  async function handleSeed() {
    setSeeding(true)
    try {
      // Seed all scenarios (clears DB first)
      await seedScenarios()
      // Recalculate scores for the new assets
      await recalculateAllScores()
      // Refresh summary
      const data = await getScoreSummary()
      setSummary(data)
    } catch (err) {
      console.error("Seeding failed:", err)
    } finally {
      setSeeding(false)
    }
  }

  if (loading) {
    return (
      <div className="slide-in flex items-center justify-center h-64">
        <p className="metal-blue hud-title text-sm animate-pulse">LOADING...</p>
      </div>
    )
  }

  const scoreColor = summary
    ? SEVERITY_COLOR[summary.severity] ?? "metal-blue"
    : "metal-blue"

  return (
    <div className="slide-in">
      <div className="flex items-center justify-between mb-10">
        <h2 className="text-3xl font-bold metal-blue hud-title">
          SECURITY OVERVIEW
        </h2>

        <button
          onClick={handleSeed}
          disabled={seeding}
          className="px-4 py-2 border border-blue-300 text-blue-300 rounded-md hover:bg-blue-300 hover:text-black transition duration-300 hud-title text-xs disabled:opacity-50"
        >
          {seeding ? "LOADING DATA..." : "LOAD DEMO DATA"}
        </button>
      </div>

      {/* Company Risk Score */}
      <div className="cyber-card mb-10 flex items-center gap-8">
        <div>
          <p className="text-gray-400 text-sm uppercase">Company Risk Score</p>
          <h3 className={`text-6xl font-bold mt-2 hud-title ${scoreColor}`}>
            {summary?.company_score ?? "—"}
          </h3>
          <span
            className={`text-xs hud-title mt-1 inline-block ${scoreColor}`}
          >
            {summary?.severity ?? "—"}
          </span>
        </div>

        <div className="flex-1 h-3 bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-1000"
            style={{
              width: `${summary?.company_score ?? 0}%`,
              background:
                summary?.severity === "CRITICAL"
                  ? "#f87171"
                  : summary?.severity === "HIGH"
                    ? "#fb923c"
                    : summary?.severity === "MEDIUM"
                      ? "#facc15"
                      : "#4ade80",
            }}
          />
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-10">
        {[
          {
            key: "assets",
            label: "Total Assets",
            value: summary?.total_assets,
            color: "metal-blue",
            tooltip: "Total discovered infrastructure including servers, services and externally reachable endpoints.",
          },
          {
            key: "critical",
            label: "Critical",
            value: summary?.critical_count,
            color: "text-red-400",
            tooltip: "Assets with a risk score ≥ 80. Require immediate attention.",
          },
          {
            key: "high",
            label: "High",
            value: summary?.high_count,
            color: "text-orange-400",
            tooltip: "Assets scoring 60–79. Should be reviewed soon.",
          },
          {
            key: "low",
            label: "Low / Medium",
            value: (summary?.low_count ?? 0) + (summary?.medium_count ?? 0),
            color: "text-green-400",
            tooltip: "Assets below risk threshold 60. Monitor regularly.",
          },
        ].map((card) => (
          <div
            key={card.key}
            className="cyber-card relative cursor-default"
            onMouseEnter={() => setHover(card.key)}
            onMouseLeave={() => setHover(null)}
          >
            <p className="text-gray-400 text-sm uppercase">{card.label}</p>
            <h3 className={`text-4xl font-bold mt-3 hud-title ${card.color}`}>
              {card.value ?? "—"}
            </h3>

            {hover === card.key && (
              <div className="absolute top-full mt-4 left-0 w-64 bg-[#14181e] border border-blue-300 text-sm text-gray-300 p-4 rounded-lg shadow-xl z-10">
                <p className="metal-blue hud-title text-xs mb-2">
                  {card.label.toUpperCase()}
                </p>
                <p>{card.tooltip}</p>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Last calculated */}
      {summary?.last_calculated && (
        <p className="text-xs text-gray-600 text-right">
          Last calculated:{" "}
          {new Date(summary.last_calculated).toLocaleString()}
        </p>
      )}
    </div>
  )
}