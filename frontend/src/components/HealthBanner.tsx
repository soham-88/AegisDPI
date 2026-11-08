import React, { useState, useEffect } from "react";
import { AlertOctagon, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";
import { HealthStatusResponse } from "@/types/aegis";

export const HealthBanner: React.FC = () => {
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        const h = await api.getHealth();
        if (mounted) setHealth(h);
      } catch {
        if (mounted) {
          setHealth({
            redis: "down",
            ml: "offline",
            engine: "stopped",
            engine_stats_fresh: false,
          });
        }
      }
    };

    check();
    const interval = setInterval(check, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (!health) return null;

  const showRedisBanner = health.redis === "down";
  const showMlBanner = health.ml === "offline";

  if (!showRedisBanner && !showMlBanner) return null;

  return (
    <div className="flex flex-col gap-2 mx-8 mt-4">
      {showRedisBanner && (
        <div className="bg-red-950/80 border border-red-500/60 text-red-200 px-4 py-3 rounded-lg flex items-center justify-between text-xs font-mono shadow-lg">
          <div className="flex items-center space-x-3">
            <AlertOctagon className="h-5 w-5 text-red-400 shrink-0" />
            <div>
              <span className="font-bold uppercase tracking-wider text-red-400 mr-2">
                REDIS DOWN:
              </span>
              <span>
                Redis unreachable — the engine fails open: traffic is forwarded, but logging, ML scoring and new blocks are paused.
              </span>
            </div>
          </div>
        </div>
      )}

      {showMlBanner && (
        <div className="bg-amber-950/80 border border-amber-500/60 text-amber-200 px-4 py-3 rounded-lg flex items-center justify-between text-xs font-mono shadow-lg">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0" />
            <div>
              <span className="font-bold uppercase tracking-wider text-amber-400 mr-2">
                ML SERVICE OFFLINE:
              </span>
              <span>
                ML service is offline — automated anomaly detection and ML auto-mitigation are paused.
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

