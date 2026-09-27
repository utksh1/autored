import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StateSummary } from "../types";
import HitLModal from "./HitLModal";

const resolveHitl = vi.fn();
vi.mock("../api", () => ({
  resolveHitl: (...args: unknown[]) => resolveHitl(...args),
}));

const baseSummary = {
  pending_hitl_gates: [],
} as unknown as StateSummary;

const gateEvent = {
  seq: 12,
  event: {
    type: "hitl_gate", gate_id: "12", gate_type: "exploit",
    target: "10.0.0.1", command: "msfconsole -x eternalblue",
    risks: ["crashes host"],
  },
};

describe("HitLModal", () => {
  // Braced body on purpose: `() => resolveHitl.mockReset()` would return the
  // mock, which vitest treats as a beforeEach cleanup hook and calls after the
  // test — producing an unhandled rejection when the last impl is mockRejectedValue.
  beforeEach(() => {
    resolveHitl.mockReset();
  });
  afterEach(cleanup);

  it("renders gate fields from the event frame and posts approve", async () => {
    resolveHitl.mockResolvedValue(undefined);
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    expect(screen.getByText(/msfconsole -x eternalblue/)).toBeTruthy();
    expect(screen.getByText("crashes host")).toBeTruthy();
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenCalledWith("eng_1", "12", true),
    );
  });

  it("closes with a note on 409 (already resolved)", async () => {
    resolveHitl.mockRejectedValue(new Error("already-resolved"));
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    await userEvent.click(screen.getByText("Reject"));
    await waitFor(() =>
      expect(screen.getByText(/already resolved/)).toBeTruthy(),
    );
  });

  it("renders nothing when no gate is pending", () => {
    const { container } = render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[]} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the newest gate frame by seq and resets on gate change", async () => {
    resolveHitl.mockResolvedValue(undefined);
    const gateA = {
      seq: 5,
      event: {
        type: "hitl_gate", gate_id: "5", gate_type: "recon",
        target: "10.0.0.5", command: "nmap -sV 10.0.0.5", risks: [],
      },
    };
    const gateB = {
      seq: 12,
      event: {
        type: "hitl_gate", gate_id: "12", gate_type: "exploit",
        target: "10.0.0.1", command: "crackmapexec smb 10.0.0.1", risks: [],
      },
    };
    const { rerender } = render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateA]} />,
    );
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() => expect(screen.getByText("approved")).toBeTruthy());

    // Real socket order: the reducer prepends frames, so the newest (B) comes
    // first. The newest must win even though gate A's frame is still around.
    rerender(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateB, gateA]} />,
    );
    expect(screen.getByText(/crackmapexec smb/)).toBeTruthy();
    expect(screen.queryByText(/nmap -sV/)).toBeNull();
    // gate id changed 5 → 12: the decided note is cleared, buttons return.
    await waitFor(() => expect(screen.getByText("Approve")).toBeTruthy());
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenLastCalledWith("eng_1", "12", true),
    );
    expect(resolveHitl).toHaveBeenCalledTimes(2);
  });

  it("falls back to the summary pending list when no frame exists (sticky)", () => {
    const pendingSummary = {
      pending_hitl_gates: [{
        gate_id: "7", gate_type: "lateral", target: "10.0.0.9",
        command: "secretsdump.py domain/admin@10.0.0.9", risks: ["noisy"],
      }],
    } as unknown as StateSummary;
    render(
      <HitLModal engagementId="eng_1" summary={pendingSummary} events={[]} />,
    );
    expect(screen.getByText(/secretsdump\.py/)).toBeTruthy();
    expect(screen.getByText("noisy")).toBeTruthy();
    expect(screen.getByText("Approve")).toBeTruthy();
  });

  it("disables Approve and Reject while a decision is in flight", async () => {
    let release: () => void = () => {};
    resolveHitl.mockImplementation(
      () => new Promise<void>((res) => { release = res; }),
    );
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    await userEvent.click(screen.getByText("Approve"));
    expect(screen.getByText("Approve")).toBeDisabled();
    expect(screen.getByText("Reject")).toBeDisabled();
    await act(async () => { release(); });
    await waitFor(() => expect(screen.getByText("approved")).toBeTruthy());
    expect(resolveHitl).toHaveBeenCalledOnce();
  });
});
