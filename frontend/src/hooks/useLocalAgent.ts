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
function readPermission(): "granted" | "denied" | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY_PERMISSION);
    if (v === "granted" || v === "denied") return v;
  } catch { /* private browsing */ }
  return null;
}
function writePermission(value: "granted" | "denied") {
  try { localStorage.setItem(STORAGE_KEY_PERMISSION, value); } catch { /* ignore */ }
}
function clearPermission() {
  try { localStorage.removeItem(STORAGE_KEY_PERMISSION); } catch { /* ignore */ }
}
function readAgentUrl(): string {
  try { return localStorage.getItem(STORAGE_KEY_URL) || DEFAULT_AGENT_URL; }
  catch { return DEFAULT_AGENT_URL; }
}
function writeAgentUrl(url: string) {
  try { localStorage.setItem(STORAGE_KEY_URL, url); } catch { /* ignore */ }
}

// ── Hook ──────────────────────────────────────────────────────────────────────
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

  const probe = useCallback(async (url?: string) => {
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
    } catch {
      setState("not-running");
    }
  }, [agentUrl]);

  // Fire initial probe for returning users (permission already granted on a previous visit)
  useEffect(() => {
    if (stored === "granted") {
      probe();
      const id = setInterval(() => probe(), POLL_INTERVAL_MS);
      setPollId(id);
      return () => clearInterval(id);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // run once on mount only

  const startPolling = useCallback((url: string) => {
    setPollId(prev => {
      if (prev) clearInterval(prev);
      probe(url);
      return setInterval(() => probe(url), POLL_INTERVAL_MS);
    });
  }, [probe]);

  const setAgentUrl = useCallback((url: string) => {
    const clean = url.trim().replace(/\/+$/, "");
    writeAgentUrl(clean);
    setAgentUrlState(clean);
  }, []);

  const grantPermission = useCallback(() => {
    writePermission("granted");
    startPolling(agentUrl);
  }, [startPolling, agentUrl]);

  const denyPermission = useCallback(() => {
    writePermission("denied");
    if (pollId) clearInterval(pollId);
    setState("permission-denied");
  }, [pollId]);

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