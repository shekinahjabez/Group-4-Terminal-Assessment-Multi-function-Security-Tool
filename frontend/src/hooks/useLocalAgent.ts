/**
 * useLocalAgent
 *
 * Manages the full lifecycle of local agent detection:
 * 1. Reads stored permission + custom agent URL from localStorage
 * 2. If granted, probes the agent URL /health endpoint
 * 3. Maps the response to one of six AgentState values
 * 4. Re-probes every 30 seconds
 * 5. Allows users to set a custom agent URL (e.g. ngrok HTTPS tunnel)
 */
import { useState, useCallback, useEffect } from "react";

export const DEFAULT_AGENT_URL = "http://127.0.0.1:8765";

const STORAGE_KEY_PERMISSION = "securekit_agent_permission";
const STORAGE_KEY_URL        = "securekit_agent_url";
const PROBE_TIMEOUT_MS        = 4_000;
const POLL_INTERVAL_MS        = 30_000;

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
  agentUrl:        string;
  setAgentUrl:     (url: string) => void;
  grantPermission: () => void;
  denyPermission:  () => void;
  resetPermission: () => void;
  recheck:         (url?: string) => void;
}

// ── Storage helpers ───────────────────────────────────────────────────────────
// reads the stored permission value from local storage
function readPermission(): "granted" | "denied" | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY_PERMISSION);
    if (v === "granted" || v === "denied") return v;
  } catch { /* private browsing */ }
  return null;
}
// saves the permission value to local storage
function writePermission(value: "granted" | "denied") {
  try { localStorage.setItem(STORAGE_KEY_PERMISSION, value); } catch { /* ignore */ }
}
// removes the stored permission from local storage
function clearPermission() {
  try { localStorage.removeItem(STORAGE_KEY_PERMISSION); } catch { /* ignore */ }
}
// reads the custom agent url from local storage or falls back to default
function readAgentUrl(): string {
  try { return localStorage.getItem(STORAGE_KEY_URL) || DEFAULT_AGENT_URL; }
  catch { return DEFAULT_AGENT_URL; }
}
// saves a custom agent url to local storage
function writeAgentUrl(url: string) {
  try { localStorage.setItem(STORAGE_KEY_URL, url); } catch { /* ignore */ }
}

// ── Hook ──────────────────────────────────────────────────────────────────────
// manages agent state, polling, and permission across the app
export function useLocalAgent(): LocalAgentHook {
  const stored = readPermission();
  const [agentUrl, setAgentUrlState] = useState<string>(readAgentUrl());
  const [state,    setState]         = useState<AgentState>(
    stored === "granted" ? "checking"
    : stored === "denied"  ? "permission-denied"
    : "permission-pending"
  );
  const [health, setHealth] = useState<AgentHealthPayload | null>(null);
  const [pollId,  setPollId] = useState<ReturnType<typeof setInterval> | null>(null);

  // hits the agent health endpoint and updates state based on the response
  const probe = useCallback(async (url?: string): Promise<boolean> => {
    const base = (url ?? agentUrl).replace(/\/+$/, "");
    setState("checking");
    try {
      const r = await fetch(`${base}/health`, {
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
        headers: {
          "ngrok-skip-browser-warning": "true",
        },
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data: AgentHealthPayload = await r.json();
      setHealth(data);
      setState(data.scapy_live ? "running-live" : "running-no-scapy");
      return true;
    } catch (err) {
      setState("not-running");
      // TypeError means the browser blocked the request (e.g. Firefox mixed-content).
      // Signal the caller to stop polling — retrying will never succeed.
      if (err instanceof TypeError) return false;
      return true;
    }
  }, [agentUrl]);

  // Fire initial probe for returning users (permission already granted on a previous visit)
  useEffect(() => {
    if (stored === "granted") {
      let id: ReturnType<typeof setInterval> | null = null;
      probe().then(keep => {
        if (!keep) return; // browser blocked (e.g. Firefox mixed-content) — stop polling
        id = setInterval(() => {
          probe().then(k => { if (!k && id !== null) { clearInterval(id!); id = null; } });
        }, POLL_INTERVAL_MS);
        setPollId(id);
      });
      return () => { if (id !== null) clearInterval(id); };
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // run once on mount only

  // starts probing the agent on a 30 second interval
  const startPolling = useCallback((url: string) => {
    setPollId(prev => {
      if (prev) clearInterval(prev);
      let id: ReturnType<typeof setInterval> | null = null;
      probe(url).then(keep => {
        if (!keep) return; // browser blocked — stop polling
        id = setInterval(() => {
          probe(url).then(k => { if (!k && id !== null) { clearInterval(id!); id = null; } });
        }, POLL_INTERVAL_MS);
        setPollId(id);
      });
      return null; // will be overwritten by setPollId inside the .then()
    });
  }, [probe]);

  // saves a new agent url and updates the state
  const setAgentUrl = useCallback((url: string) => {
    const clean = url.trim().replace(/\/+$/, "");
    writeAgentUrl(clean);
    setAgentUrlState(clean);
  }, []);

  // stores granted permission and immediately starts probing the agent
  const grantPermission = useCallback(() => {
    writePermission("granted");
    startPolling(agentUrl);
  }, [startPolling, agentUrl]);

  // stores denied permission and stops polling
  const denyPermission = useCallback(() => {
    writePermission("denied");
    if (pollId) clearInterval(pollId);
    setState("permission-denied");
  }, [pollId]);

  // clears stored permission and goes back to the pending state
  const resetPermission = useCallback(() => {
    clearPermission();
    if (pollId) clearInterval(pollId);
    setState("permission-pending");
    setHealth(null);
  }, [pollId]);

  return {
    state,
    health,
    agentUrl,
    setAgentUrl,
    grantPermission,
    denyPermission,
    resetPermission,
    recheck: (url?: string) => probe(url ?? agentUrl),
  };
}