import { Link } from "react-router-dom"

export default function Sidebar() {

  return (

    <div className="w-64 bg-black/30 backdrop-blur-md p-6 border-r border-gray-800">

      <h1 className="text-2xl font-bold mb-10 metal-blue hud-title">
        CyberSentry
      </h1>

      <nav className="flex flex-col gap-3">

        <Link className="cyber-tab text-gray-300 hover:text-blue-300" to="/">
          Dashboard
        </Link>

        <Link className="cyber-tab text-gray-300 hover:text-blue-300" to="/assets">
          Assets
        </Link>

        <Link className="cyber-tab text-gray-300 hover:text-blue-300" to="/graph">
          Attack Graph
        </Link>

        <Link className="cyber-tab text-gray-300 hover:text-blue-300" to="/tasks">
          Hardening Tasks
        </Link>

      </nav>

    </div>

  )

}