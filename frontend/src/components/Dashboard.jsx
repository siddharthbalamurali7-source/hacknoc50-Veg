import { useState } from "react"

export default function Dashboard() {

  const [hover, setHover] = useState(null)

  return (

    <div className="slide-in">

      <h2 className="text-3xl font-bold mb-10 metal-blue hud-title">
        SECURITY OVERVIEW
      </h2>

      <div className="grid grid-cols-3 gap-10">

        {/* TOTAL ASSETS */}

        <div
          className="cyber-card relative cursor-default transition duration-300"
          onMouseEnter={() => setHover("assets")}
          onMouseLeave={() => setHover(null)}
        >

          <p className="text-gray-400 text-sm uppercase">
            Total Assets
          </p>

          <h3 className="text-4xl font-bold mt-3 metal-blue hud-title">
            12
          </h3>

          {hover === "assets" && (

            <div className="absolute top-full mt-4 left-0 w-64 bg-[#14181e] border border-blue-300 text-sm text-gray-300 p-4 rounded-lg shadow-xl transition-all duration-300">

              <p className="metal-blue hud-title text-xs mb-2">
                ASSET SUMMARY
              </p>

              <p>
                Total discovered infrastructure including servers,
                services and externally reachable endpoints.
              </p>

            </div>

          )}

        </div>



        {/* CRITICAL ASSETS */}

        <div
          className="cyber-card relative cursor-default transition duration-300"
          onMouseEnter={() => setHover("critical")}
          onMouseLeave={() => setHover(null)}
        >

          <p className="text-gray-400 text-sm uppercase">
            Critical Assets
          </p>

          <h3 className="text-4xl font-bold mt-3 text-red-400 hud-title">
            3
          </h3>

          {hover === "critical" && (

            <div className="absolute top-full mt-4 left-0 w-64 bg-[#14181e] border border-blue-300 text-sm text-gray-300 p-4 rounded-lg shadow-xl transition-all duration-300">

              <p className="metal-blue hud-title text-xs mb-2">
                HIGH VALUE TARGETS
              </p>

              <p>
                Sensitive infrastructure including authentication servers,
                production databases and external-facing services.
              </p>

            </div>

          )}

        </div>



        {/* OPEN CVES */}

        <div
          className="cyber-card relative cursor-default transition duration-300"
          onMouseEnter={() => setHover("cves")}
          onMouseLeave={() => setHover(null)}
        >

          <p className="text-gray-400 text-sm uppercase">
            Open CVEs
          </p>

          <h3 className="text-4xl font-bold mt-3 metal-blue hud-title">
            27
          </h3>

          {hover === "cves" && (

            <div className="absolute top-full mt-4 left-0 w-64 bg-[#14181e] border border-blue-300 text-sm text-gray-300 p-4 rounded-lg shadow-xl transition-all duration-300">

              <p className="metal-blue hud-title text-xs mb-2">
                VULNERABILITY COUNT
              </p>

              <p>
                Active vulnerabilities detected across services based
                on current CVE intelligence feeds and scan results.
              </p>

            </div>

          )}

        </div>

      </div>

    </div>

  )

}