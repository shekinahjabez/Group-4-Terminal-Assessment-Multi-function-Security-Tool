/**
 * useLocalAgent
 *
 * Manages the full lifecycle of local agent detection:
 * 1. Reads stored permission from localStorage
 * 2. If granted, probes http://127.0.0.1:8765/health
 * 3. Maps the response to one of six AgentState values
 * 4. Re-probes every 30 seconds so the badge updates when
 *    the developer starts or stops the agent mid-session
 */
import { useState, useEffect, useCallback } from "react";

export const LOCAL_AGENT = "http://127.0.0.1:8765";
const HEALTH_URL      = `${LOCAL_AGENT}/health`;
const STORAGE_KEY     = "securekit_agent_permission";
const PROBE_TIMEOUT_MS = 2_000;
const POLL_INTERVAL_MS = 30_000;

export type AgentState =
  | "permission-pending"
  | "permission-denied"
  | "checking"
  | "running-live"
  | "running-no-scapy"
  | "not-running";

export interface AgentHealthPayload {
  scapy_live:  boolean;
  scapy_error: string | null;
  privileged:  boolean;
  os:          "linux" | "darwin" | "windows" | string;
  version:     string;
}

export interface LocalAgentHook {
  state:           AgentState;
  health:          AgentHealthPayload | null;
  grantPermission: () => void;
  denyPermission:  () => void;
  resetPermission: () => void;
  recheck:         () => void;
}

function readPermission(): "granted" | "denied" | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "granted" || v === "denied") return v;
  } catch { /* private browsing */ }
  return null;
}

function writePermission(value: "granted" | "denied") {
  try { localStorage.setItem(STORAGE_KEY, value); } catch { /* ignore */ }
}

function clearPermission() {
  try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
}

export function useLocalAgent(): LocalAgentHook {
  const stored = readPermission();
  const [state, setState] = useState<AgentState>(
    stored === "granted" ? "checking"
    : stored === "denied" ? "permission-denied"
    : "permission-pending"
  );
  const [health, setHealth] = useState<AgentHealthPayload | null>(null);

  const probe = useCallback(async () => {
    setState("checking");
    try {
      const r = await fetch(HEALTH_URL, {
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data: AgentHealthPayload = await r.json();
      setHealth(data);
      setState(data.scapy_live ? "running-live" : "running-no-scapy");
    } catch {
      setState("not-running");
    }
  }, []);

  useEffect(() => {
    if (
      state === "checking" ||
      state === "running-live" ||
      state === "running-no-scapy" ||
      state === "not-running"
    ) {
      probe();
      const id = setInterval(probe, POLL_INTERVAL_MS);
      return () => clearInterval(id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const grantPermission = useCallback(() => {
    writePermission("granted");
    probe();
  }, [probe]);

  const denyPermission = useCallback(() => {
    writePermission("denied");
    setState("permission-denied");
  }, []);

  const resetPermission = useCallback(() => {
    clearPermission();
    setState("permission-pending");
    setHealth(null);
  }, []);

  return {
    state,
    health,
    grantPermission,
    denyPermission,
    resetPermission,
    recheck: probe,
  };
}