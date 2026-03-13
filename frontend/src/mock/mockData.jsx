export const mockData = {
  
  assets: [
    {
      id: 1,
      hostname: "web-server-01",
      ip_address: "10.0.1.10",
      os: "Linux",
      internet_exposed: true,
      open_ports: [80, 443, 22],
      software_list: [
        { name: "Apache", version: "2.4.41" },
        { name: "OpenSSL", version: "1.1.1" },
      ],
      criticality: 4,
      risk_score: 87,
      severity_label: "CRITICAL",
      last_scanned: "2024-01-15T10:30:00Z",
      last_scored: "2024-01-15T10:35:00Z",
    },
    {
      id: 2,
      hostname: "app-server-01",
      ip_address: "10.0.1.11",
      os: "Linux",
      internet_exposed: false,
      open_ports: [8080, 5432],
      software_list: [
        { name: "Node.js", version: "16.14.0" },
        { name: "PostgreSQL", version: "13.4" },
      ],
      criticality: 3,
      risk_score: 62,
      severity_label: "HIGH",
      last_scanned: "2024-01-15T10:30:00Z",
      last_scored: "2024-01-15T10:35:00Z",
    },
    {
      id: 3,
      hostname: "db-server-01",
      ip_address: "10.0.1.12",
      os: "Windows Server 2019",
      internet_exposed: false,
      open_ports: [1433, 3389],
      software_list: [
        { name: "MSSQL", version: "15.0.2000" },
      ],
      criticality: 5,
      risk_score: 91,
      severity_label: "CRITICAL",
      last_scanned: "2024-01-10T08:00:00Z",
      last_scored: "2024-01-10T08:05:00Z",
    },
    {
      id: 4,
      hostname: "dev-workstation-04",
      ip_address: "10.0.2.20",
      os: "Ubuntu 22.04",
      internet_exposed: false,
      open_ports: [22],
      software_list: [
        { name: "OpenSSH", version: "8.9" },
      ],
      criticality: 1,
      risk_score: 28,
      severity_label: "LOW",
      last_scanned: "2024-01-15T09:00:00Z",
      last_scored: "2024-01-15T09:05:00Z",
    },
  ],


  scores: [
    {
      asset_id: 3,
      hostname: "db-server-01",
      score: 91,
      severity: "CRITICAL",
      top_cves: ["CVE-2021-44228", "CVE-2020-0796"],
      breakdown: { ports: 25, cves: 35, criticality: 25, patch_age: 6 },
    },
    {
      asset_id: 1,
      hostname: "web-server-01",
      score: 87,
      severity: "CRITICAL",
      top_cves: ["CVE-2021-41773", "CVE-2022-22965"],
      breakdown: { ports: 20, cves: 30, criticality: 20, patch_age: 17 },
    },
    {
      asset_id: 2,
      hostname: "app-server-01",
      score: 62,
      severity: "HIGH",
      top_cves: ["CVE-2021-34527"],
      breakdown: { ports: 15, cves: 22, criticality: 15, patch_age: 10 },
    },
    {
      asset_id: 4,
      hostname: "dev-workstation-04",
      score: 28,
      severity: "LOW",
      top_cves: [],
      breakdown: { ports: 8, cves: 5, criticality: 5, patch_age: 10 },
    },
  ],


  summary: {
    company_score: 67,
    severity: "HIGH",
    total_assets: 4,
    critical_count: 2,
    high_count: 1,
    medium_count: 0,
    low_count: 1,
    last_calculated: "2024-01-15T10:35:00Z",
  },

  scoreHistory: {
    1: [
      { score: 70, severity: "HIGH", calculated_at: "2024-01-10T10:00:00Z" },
      { score: 78, severity: "HIGH", calculated_at: "2024-01-12T10:00:00Z" },
      { score: 87, severity: "CRITICAL", calculated_at: "2024-01-15T10:35:00Z" },
    ],
    2: [
      { score: 55, severity: "MEDIUM", calculated_at: "2024-01-10T10:00:00Z" },
      { score: 62, severity: "HIGH", calculated_at: "2024-01-15T10:35:00Z" },
    ],
    3: [
      { score: 85, severity: "CRITICAL", calculated_at: "2024-01-10T08:05:00Z" },
      { score: 91, severity: "CRITICAL", calculated_at: "2024-01-15T10:35:00Z" },
    ],
    4: [
      { score: 28, severity: "LOW", calculated_at: "2024-01-15T09:05:00Z" },
    ],
  },


  tasks: [
    {
      id: "3-0",
      asset_id: 3,
      hostname: "db-server-01",
      description: "Patch CVE-2021-44228 on db-server-01",
      cve_id: "CVE-2021-44228",
      priority: "Critical",
      fix: { type: "patch_cve", cve_id: "CVE-2021-44228" },
    },
    {
      id: "3-1",
      asset_id: 3,
      hostname: "db-server-01",
      description: "Patch CVE-2020-0796 on db-server-01",
      cve_id: "CVE-2020-0796",
      priority: "Critical",
      fix: { type: "patch_cve", cve_id: "CVE-2020-0796" },
    },
    {
      id: "1-0",
      asset_id: 1,
      hostname: "web-server-01",
      description: "Patch CVE-2021-41773 on web-server-01",
      cve_id: "CVE-2021-41773",
      priority: "Critical",
      fix: { type: "patch_cve", cve_id: "CVE-2021-41773" },
    },
    {
      id: "1-1",
      asset_id: 1,
      hostname: "web-server-01",
      description: "Close SSH port (22) on web-server-01",
      cve_id: null,
      priority: "High",
      fix: { type: "close_port", port: 22 },
    },
    {
      id: "2-0",
      asset_id: 2,
      hostname: "app-server-01",
      description: "Patch CVE-2021-34527 on app-server-01",
      cve_id: "CVE-2021-34527",
      priority: "High",
      fix: { type: "patch_cve", cve_id: "CVE-2021-34527" },
    },
  ],

  // ── Attack graph (built from assets) ─────────────────────────────────────
  attackGraph: {
    nodes: [
      { data: { id: "internet", label: "Internet", risk: 10 } },
      { data: { id: "1", label: "web-server-01", risk: 87, severity: "CRITICAL" } },
      { data: { id: "2", label: "app-server-01", risk: 62, severity: "HIGH" } },
      { data: { id: "3", label: "db-server-01", risk: 91, severity: "CRITICAL" } },
      { data: { id: "4", label: "dev-ws-04", risk: 28, severity: "LOW" } },
    ],
    edges: [
      { data: { source: "internet", target: "1" } },
      { data: { source: "1", target: "2" } },
      { data: { source: "2", target: "3" } },
    ],
  },
}