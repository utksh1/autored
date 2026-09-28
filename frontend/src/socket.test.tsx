import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useEngagementSocket } from "./socket";

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(public url: string) { MockWebSocket.instances.push(this); }
  close() { this.onclose?.(); }
  send() {}
}

const fetchState = vi.fn();
vi.mock("./api", () => ({ fetchState: (...a: unknown[]) => fetchState(...a) }));

describe("useEngagementSocket", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    fetchState.mockReset();
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("seeds from hello and resyncs from GET /state after a drop", async () => {
    fetchState.mockResolvedValue({ phase: "recon", pending_hitl_gates: [] });
    const { result } = renderHook(() => useEngagementSocket("eng_1"));
    const ws = MockWebSocket.instances[0];
    expect(ws.url.endsWith("/ws/eng_1")).toBe(true);
    ws.onopen?.();
    ws.onmessage?.({
      data: JSON.stringify({
        type: "hello", engagement_id: "eng_1", seq: 0,
        state_summary: { phase: "recon", pending_hitl_gates: [] },
      }),
    });
    await waitFor(() => expect(result.current.summary?.phase).toBe("recon"));
    expect(result.current.connected).toBe(true);
    // drop → immediate resync fetch (initial + resync = 2 calls)
    ws.onclose?.();
    await waitFor(() => expect(fetchState).toHaveBeenCalledTimes(2));
    expect(result.current.connected).toBe(false);
  });

  it("keeps summary null when hello arrives before the first snapshot", async () => {
    fetchState.mockRejectedValue(new Error("404"));
    const { result } = renderHook(() => useEngagementSocket("eng_2"));
    const ws = MockWebSocket.instances[0];
    ws.onopen?.();
    ws.onmessage?.({
      data: JSON.stringify({
        type: "hello", engagement_id: "eng_2", seq: 0, state_summary: {},
      }),
    });
    await waitFor(() => expect(result.current.connected).toBe(true));
    expect(result.current.summary).toBeNull();
  });

  it("does not duplicate events when hello replays after a reconnect", async () => {
    fetchState.mockResolvedValue({ phase: "recon", pending_hitl_gates: [] });
    const { result } = renderHook(() => useEngagementSocket("eng_3"));
    const first = MockWebSocket.instances[0];
    first.onopen?.();
    const frame = (seq: number) => ({
      data: JSON.stringify({
        type: "event", seq,
        event: { type: "tool_call", tool: `tool-${seq}` },
      }),
    });
    first.onmessage?.(frame(1));
    first.onmessage?.(frame(2));
    await waitFor(() => expect(result.current.events).toHaveLength(2));

    // Drop → reconnect → server replays the ring buffer via a second hello
    // carrying the same frames. The pre-drop events must be cleared, not
    // duplicated (activity log shows each entry once).
    first.onclose?.();
    // Reconnect is scheduled after the 1 s initial backoff — allow for it.
    const second = await waitFor(
      () => {
        expect(MockWebSocket.instances.length).toBeGreaterThan(1);
        return MockWebSocket.instances[1];
      },
      { timeout: 3000 },
    );
    second.onopen?.();
    second.onmessage?.({
      data: JSON.stringify({
        type: "hello", engagement_id: "eng_3", seq: 2,
        state_summary: { phase: "recon", pending_hitl_gates: [] },
      }),
    });
    second.onmessage?.(frame(1));
    second.onmessage?.(frame(2));
    await waitFor(() => expect(result.current.events).toHaveLength(2));
    const seqs = result.current.events.map((f) => f.seq);
    expect(new Set(seqs).size).toBe(seqs.length);
  });
});
