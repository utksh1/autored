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
});
