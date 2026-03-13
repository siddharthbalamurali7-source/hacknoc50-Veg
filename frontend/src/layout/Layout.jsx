import Sidebar from "./Sidebar"
import HUD from "../components/HUD"

export default function Layout({ children }) {
  return (
    <div className="flex min-h-screen bg-gray-900 text-gray-200">

      {/* Sidebar */}
      <Sidebar />

      {/* Main content */}
      <main className="flex-1 p-10 relative">

        <div className="max-w-7xl mx-auto">
          {children}
        </div>

      </main>

      {/* Floating HUD */}
      <HUD />

    </div>
  )
}