import { BrowserRouter, Routes, Route } from "react-router-dom"

import Layout from "./layout/Layout"
import DashboardPage from "./pages/DashboardPage"
import AssetsPage from "./pages/AssetsPage"
import GraphPage from "./pages/GraphPage"
import TasksPage from "./pages/TasksPage"

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/graph" element={<GraphPage />} />
          <Route path="/tasks" element={<TasksPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App