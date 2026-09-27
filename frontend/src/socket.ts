import { useEffect, useReducer, useRef } from "react";
import { fetchState } from "./api";
import type { StateSummary } from "./types";

export interface EventFrame {
  seq: number;
  event: Record<string, unknown> & { type: string; node?: string };
}

interface SocketState {
  summary: StateSummary | null;
  events: EventFrame[];
  connected: boolean;
}

type Action =
  | { kind: "hello"; summary: StateSummary }
  | { kind: "event"; frame: EventFrame }
  | { kind: "state"; summary: StateSummary }
  | { kind: "connected"; connected: boolean };

function reducer(state: SocketState, action: Action): SocketState {
  switch (action.kind) {
    case "hello": {
      // A hello that arrives before the first snapshot carries `{}` (the
      // bridge seeds _last_summary empty) — keep summary null so the view
      // stays on its loading line instead of crashing on missing fields.
      const summary =
        Object.keys(action.summary).length > 0 ? action.summary : state.summary;
      return { ...state, summary, connected: true };
    }
    case "event":
      return { ...state, events: [action.frame, ...state.events].slice(0, 500) };
    case "state":
      return { ...state, summary: action.summary };
    case "connected":
      return { ...state, connected: action.connected };
  }
}

const PHASES = ["recon", "vuln", "exploit", "postex", "lateral", "cleanup", "report", "done"];

export function useEngagementSocket(id: string) {
  const [state, dispatch] = useReducer(reducer, {
    summary: null, events: [], connected: false,
  });
  const backoff = useRef(1000);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;

    async function resync() {
      try {
        const summary = await fetchState(id);
        dispatch({ kind: "state", summary });
      } catch { /* 404 before run starts — WS retry covers it */ }
    }

    function connect() {
      if (closed) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/${id}`);
      ws.onopen = () => { backoff.current = 1000; dispatch({ kind: "connected", connected: true }); };
      ws.onmessage = (msg) => {
        const frame = JSON.parse(msg.data);
        if (frame.type === "hello") dispatch({ kind: "hello", summary: frame.state_summary });
        else if (frame.type === "state") dispatch({ kind: "state", summary: frame.state_summary });
        else if (frame.type === "event") {
          dispatch({ kind: "event", frame });
          if (frame.event?.type === "phase_change") void resync();
        }
      };
      ws.onclose = () => {
        dispatch({ kind: "connected", connected: false });
        if (closed) return;
        void resync(); // spec §8: reconnect re-syncs from GET /state
        setTimeout(connect, backoff.current);
        backoff.current = Math.min(backoff.current * 2, 30_000);
      };
    }

    void resync();
    connect();
    return () => { closed = true; ws?.close(); };
  }, [id]);

  return state;
}

export { PHASES };
