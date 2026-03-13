import { useEffect, useState } from "react"
import { getTasks, simulateFix, applyFix, getScoreSummary } from "../api/client"

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
  const [applying, setApplying] = useState(null)
  const [simResult, setSimResult] = useState({})

  async function loadTasks() {
    try {
      const data = await getTasks()
      setTasks(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error("Tasks failed to load:", err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTasks()
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

  async function handleApply(task) {
    if (!confirm(`Are you sure you want to apply this fix to ${task.hostname}?`)) return

    setApplying(task.id)
    try {
      await applyFix(task.asset_id, task.fix)
      // Refresh tasks list
      await loadTasks()
      // Note: In a real app we'd use a global state (Context/Redux) to refresh the HUD score
      // For now, the user will see it update on page change or refresh.
    } catch (e) {
      console.error("Apply fix failed", e)
      alert("Failed to apply fix. see console.")
    } finally {
      setApplying(null)
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
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold metal-blue hud-title uppercase">
          Hardening Queue
        </h2>
        <span className="text-xs text-gray-500 hud-title">
          {tasks.length} {tasks.length === 1 ? 'TASK' : 'TASKS'} PENDING
        </span>
      </div>

      {tasks.length === 0 ? (
        <div className="cyber-card text-center text-gray-500 py-12">
          <p className="hud-title text-sm">SECURE — NO TASKS PENDING</p>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {tasks.map((task) => {
            const priorityStyle =
              PRIORITY_STYLES[task.priority] ?? "text-gray-400 border-gray-400"
            const result = simResult[task.id]

            return (
              <div key={task.id} className="cyber-card group">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span
                        className={`border px-2 py-0.5 rounded text-[10px] hud-title font-bold ${priorityStyle}`}
                      >
                        {task.priority.toUpperCase()}
                      </span>
                      {task.type === "close_port" ? (
                        <span className="text-[10px] text-blue-300 hud-title border border-blue-400 px-2 py-0.5 rounded">
                          PORT CLOSURE
                        </span>
                      ) : (
                        <span className="text-[10px] text-red-300 hud-title border border-red-400 px-2 py-0.5 rounded">
                          VULNERABILITY PATCH
                        </span>
                      )}
                    </div>

                    <p className="text-gray-200 text-sm font-medium">{task.description}</p>

                    <p className="text-[10px] text-gray-500 mt-2 uppercase tracking-wider">
                      Affected Asset:{" "}
                      <span className="text-blue-200">
                        {task.hostname ?? `#${task.asset_id}`}
                      </span>
                    </p>
                  </div>

                  <div className="flex flex-col gap-2">
                    <button
                      onClick={() => handleSimulate(task)}
                      disabled={simulating === task.id || applying === task.id}
                      className="px-4 py-1.5 border border-blue-400/50 text-blue-300 rounded hover:bg-blue-400/10 transition-all hud-title text-[10px] disabled:opacity-50"
                    >
                      {simulating === task.id ? "SIMULATING..." : "SIMULATE"}
                    </button>
                    <button
                      onClick={() => handleApply(task)}
                      disabled={applying === task.id}
                      className="px-4 py-1.5 bg-blue-500/10 border border-blue-400 text-blue-400 rounded hover:bg-blue-400 hover:text-black transition-all hud-title text-[10px] font-bold disabled:opacity-50"
                    >
                      {applying === task.id ? "APPLYING..." : "APPLY FIX"}
                    </button>
                  </div>
                </div>

                {/* Simulation result */}
                {result && (
                  <div className="mt-4 pt-4 border-t border-blue-900/30 grid grid-cols-3 gap-4 text-[10px]">
                    <div className="text-center p-2 rounded bg-gray-900/50">
                      <p className="text-gray-500 mb-1">SCORE</p>
                      <p className="text-orange-400 hud-title text-lg font-bold">
                        {result.old_score}
                      </p>
                    </div>
                    <div className="text-center p-2 rounded bg-blue-900/10 border border-blue-500/20">
                      <p className="text-blue-400/70 mb-1">PREDICTED</p>
                      <p className="text-green-400 hud-title text-lg font-bold">
                        {result.new_score}
                      </p>
                    </div>
                    <div className="text-center p-2 rounded bg-gray-900/50">
                      <p className="text-gray-500 mb-1">IMPROVEMENT</p>
                      <p
                        className={`hud-title text-lg font-bold ${result.delta < 0 ? "text-green-400" : "text-gray-400"
                          }`}
                      >
                        {result.delta < 0 ? result.delta : "0.0"}
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