import { useEffect, useState } from "react"
import { getTasks, simulateFix } from "../api/client"

const PRIORITY_STYLES = {
  Critical: "text-red-400 border-red-400",
  High: "text-orange-400 border-orange-400",
  Medium: "text-yellow-400 border-yellow-400",
  Low: "text-green-400 border-green-400",
}

export default function TaskQueue() {
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(true)
  const [simulating, setSimulating] = useState(null)
  const [simResult, setSimResult] = useState({})

  useEffect(() => {
    getTasks().then((data) => {
      setTasks(data)
      setLoading(false)
    })
  }, [])

  async function handleSimulate(task) {
    setSimulating(task.id)
    try {
      const result = await simulateFix(task.asset_id, task.fix)
      setSimResult((prev) => ({ ...prev, [task.id]: result }))
    } catch (e) {
      console.error("Simulation failed", e)
    } finally {
      setSimulating(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-40">
        <p className="metal-blue hud-title text-sm animate-pulse">LOADING TASKS...</p>
      </div>
    )
  }

  return (
    <div className="slide-in">
      <h2 className="text-2xl font-bold mb-6 metal-blue hud-title">
        HARDENING TASKS
      </h2>

      {tasks.length === 0 ? (
        <div className="cyber-card text-center text-gray-500 py-12">
          <p className="hud-title text-sm">NO TASKS — SYSTEM CLEAN</p>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {tasks.map((task) => {
            const priorityStyle =
              PRIORITY_STYLES[task.priority] ?? "text-gray-400 border-gray-400"
            const result = simResult[task.id]

            return (
              <div key={task.id} className="cyber-card">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span
                        className={`border px-2 py-0.5 rounded text-xs hud-title ${priorityStyle}`}
                      >
                        {task.priority.toUpperCase()}
                      </span>
                      {task.cve_id && (
                        <span className="text-xs text-red-300 hud-title">
                          {task.cve_id}
                        </span>
                      )}
                    </div>

                    <p className="text-gray-200 text-sm">{task.description}</p>

                    <p className="text-xs text-gray-500 mt-1">
                      Asset:{" "}
                      <span className="text-gray-400">
                        {task.hostname ?? `#${task.asset_id}`}
                      </span>
                    </p>
                  </div>

                  <button
                    onClick={() => handleSimulate(task)}
                    disabled={simulating === task.id}
                    className="shrink-0 px-4 py-2 border border-blue-300 text-blue-300 rounded-md hover:bg-blue-300 hover:text-black transition duration-300 hud-title text-xs disabled:opacity-50"
                  >
                    {simulating === task.id ? "SIMULATING..." : "SIMULATE FIX"}
                  </button>
                </div>

                {/* Simulation result */}
                {result && (
                  <div className="mt-4 pt-4 border-t border-gray-700 grid grid-cols-3 gap-4 text-xs">
                    <div className="text-center">
                      <p className="text-gray-500 mb-1">CURRENT SCORE</p>
                      <p className="text-orange-400 hud-title text-xl font-bold">
                        {result.current_score}
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-gray-500 mb-1">PREDICTED SCORE</p>
                      <p className="text-green-400 hud-title text-xl font-bold">
                        {result.predicted_score}
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-gray-500 mb-1">DELTA</p>
                      <p
                        className={`hud-title text-xl font-bold ${
                          result.delta < 0 ? "text-green-400" : "text-red-400"
                        }`}
                      >
                        {result.delta > 0 ? "+" : ""}
                        {result.delta}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}