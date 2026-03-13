import { useEffect, useState } from "react"
import { getScoreSummary } from "../api/client"

const SEVERITY_COLOR = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#4ade80",
}

export default function HUD() {
  const [summary, setSummary] = useState(null)

  useEffect(() => {
    getScoreSummary().then(setSummary)
    const interval = setInterval(() => {
      getScoreSummary().then(setSummary)
    }, 30000) // refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const color = summary ? SEVERITY_COLOR[summary.severity] ?? "#7fbfff" : "#7fbfff"

  return (
    <div className="fixed bottom-6 right-6 hud-panel p-4 cursor-default transition-all duration-300 min-w-[160px]">
      <p className="text-sm metal-blue hud-title">SYSTEM STATUS</p>

      <div className="text-xs text-gray-300 mt-2">
        Assets:{" "}
        <span className="text-white font-bold">
          {summary?.total_assets ?? "—"}
        </span>
      </div>

      <div className="text-xs mt-1" style={{ color }}>
        Threat Level:{" "}
        <span className="font-bold hud-title">
          {summary?.severity ?? "—"}
        </span>
      </div>

      <div className="text-xs text-gray-300 mt-1">
        Risk Score:{" "}
        <span className="font-bold" style={{ color }}>
          {summary?.company_score ?? "—"}
        </span>
      </div>

      <div className="text-xs text-gray-500 mt-2">
        Critical:{" "}
        <span className="text-red-400">{summary?.critical_count ?? 0}</span>
        {"  "}
        High:{" "}
        <span className="text-orange-400">{summary?.high_count ?? 0}</span>
      </div>
    </div>
  )
}