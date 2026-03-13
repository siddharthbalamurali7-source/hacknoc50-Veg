import { mockData } from "../mock/mockData"

const USE_MOCK = false
const BASE_URL = "http://localhost:8000"

// ─── ASSETS ──────────────────────────────────────────────────────────────────

export async function getAssets(filters = {}) {
  if (USE_MOCK) return mockData.assets

  const params = new URLSearchParams()
  if (filters.internet_exposed !== undefined)
    params.append("internet_exposed", filters.internet_exposed)
  if (filters.min_criticality !== undefined)
    params.append("min_criticality", filters.min_criticality)

  const res = await fetch(`${BASE_URL}/assets/?${params}`)
  return res.json()
}

export async function getAsset(assetId) {
  if (USE_MOCK) return mockData.assets.find((a) => a.id === assetId) ?? null

  const res = await fetch(`${BASE_URL}/assets/${assetId}`)
  return res.json()
}

export async function triggerScan(ipRange = "192.168.1.0/24", ports = "1-1024", useSeed = false) {
  if (USE_MOCK) return { message: "Scan complete (mock)", assets_found: mockData.assets.length }

  const res = await fetch(`${BASE_URL}/assets/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip_range: ipRange, ports, use_seed: useSeed }),
  })
  return res.json()
}

export async function seedAssets() {
  if (USE_MOCK) return { message: "Seeded (mock)", assets_found: mockData.assets.length }

  const res = await fetch(`${BASE_URL}/assets/seed`, { method: "POST" })
  return res.json()
}

export async function deleteAsset(assetId) {
  if (USE_MOCK) return { message: "Deleted (mock)" }

  const res = await fetch(`${BASE_URL}/assets/${assetId}`, { method: "DELETE" })
  return res.json()
}

// ─── SCORES ──────────────────────────────────────────────────────────────────

export async function getAllScores() {
  if (USE_MOCK) return mockData.scores

  const res = await fetch(`${BASE_URL}/scores/`)
  return res.json()
}

export async function getScoreSummary() {
  if (USE_MOCK) return mockData.summary

  const res = await fetch(`${BASE_URL}/scores/summary`)
  return res.json()
}

export async function getAssetScore(assetId) {
  if (USE_MOCK) return mockData.scores.find((s) => s.asset_id === assetId) ?? null

  const res = await fetch(`${BASE_URL}/scores/${assetId}`)
  return res.json()
}

export async function getScoreHistory(assetId, limit = 30) {
  if (USE_MOCK) return mockData.scoreHistory[assetId] ?? []

  const res = await fetch(`${BASE_URL}/scores/${assetId}/history?limit=${limit}`)
  return res.json()
}

export async function recalculateAllScores() {
  if (USE_MOCK) return { message: "Recalculated (mock)" }

  const res = await fetch(`${BASE_URL}/scores/recalculate`, { method: "POST" })
  return res.json()
}

export async function recalculateAssetScore(assetId) {
  if (USE_MOCK) return mockData.scores.find((s) => s.asset_id === assetId) ?? null

  const res = await fetch(`${BASE_URL}/scores/recalculate/${assetId}`, { method: "POST" })
  return res.json()
}

export async function simulateFix(assetId, fix) {
  // fix example: { type: "close_port", port: 22 }
  // or:          { type: "patch_cve", cve_id: "CVE-2021-44228" }
  if (USE_MOCK) {
    return {
      asset_id: assetId,
      current_score: 75,
      predicted_score: 58,
      delta: -17,
      fix_applied: fix,
    }
  }

  const res = await fetch(`${BASE_URL}/scores/simulate-fix/${assetId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(fix),
  })
  return res.json()
}

// ─── ATTACK GRAPH (built from assets + scores, no dedicated endpoint) ─────────

export async function getAttackGraph() {
  if (USE_MOCK) return mockData.attackGraph

  // Build graph from real data
  const [assets, scores] = await Promise.all([
    fetch(`${BASE_URL}/assets/`).then((r) => r.json()),
    fetch(`${BASE_URL}/scores/`).then((r) => r.json()),
  ])

  const scoreMap = {}
  scores.forEach((s) => { scoreMap[s.asset_id] = s.score })

  // Always include an "internet" entry node
  const nodes = [
    { data: { id: "internet", label: "Internet", risk: 10 } },
    ...assets.map((a) => ({
      data: {
        id: String(a.id),
        label: a.hostname || a.ip_address,
        risk: scoreMap[a.id] ?? 0,
        severity: a.severity_label,
      },
    })),
  ]

  // Connect internet → exposed assets; connect all others in chain
  const edges = []
  assets.forEach((a) => {
    if (a.internet_exposed) {
      edges.push({ data: { source: "internet", target: String(a.id) } })
    }
  })
  // Simple chain: link assets by id order as a demonstration path
  for (let i = 0; i < assets.length - 1; i++) {
    edges.push({
      data: { source: String(assets[i].id), target: String(assets[i + 1].id) },
    })
  }

  return { nodes, edges }
}

// ─── TASKS (derived from top CVEs / high-risk assets) ──────────────────────

export async function getTasks() {
  if (USE_MOCK) return mockData.tasks

  // Backend has no dedicated /tasks endpoint.
  // We derive hardening tasks from high-risk scores.
  const scores = await fetch(`${BASE_URL}/scores/`).then((r) => r.json())
  const tasks = []

  scores.forEach((s) => {
    if (!s.top_cves) return
    s.top_cves.forEach((cve, i) => {
      tasks.push({
        id: `${s.asset_id}-${i}`,
        asset_id: s.asset_id,
        hostname: s.hostname,
        description: `Patch ${cve} on ${s.hostname || `Asset #${s.asset_id}`}`,
        cve_id: cve,
        priority: s.severity === "CRITICAL" ? "Critical" : s.severity === "HIGH" ? "High" : "Medium",
        fix: { type: "patch_cve", cve_id: cve },
      })
    })
  })

  return tasks
}