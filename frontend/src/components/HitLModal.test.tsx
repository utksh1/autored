import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HitlGate, StateSummary } from "../types";
import HitLModal from "./HitLModal";

const resolveHitl = vi.fn();
vi.mock("../api", () => ({
  resolveHitl: (...args: unknown[]) => resolveHitl(...args),
}));

const gateEvent = {
  seq: 12,
  event: {
    type: "hitl_gate", gate_id: "12", gate_type: "exploit",
    target: "10.0.0.1", command: "msfconsole -x eternalblue",
    risks: ["crashes host"],
  },
};

const gateFor = (id: string, command: string): HitlGate => ({
  gate_id: id, gate_type: "exploit", target: "10.0.0.1",
  command, risks: ["crashes host"],
});

const summaryFor = (...gates: HitlGate[]) =>
  ({ pending_hitl_gates: gates }) as unknown as StateSummary;

describe("HitLModal", () => {
  // Braced body on purpose: `() => resolveHitl.mockReset()` would return the
  // mock, which vitest treats as a beforeEach cleanup hook and calls after the
  // test — producing an unhandled rejection when the last impl is mockRejectedValue.
  beforeEach(() => {
    resolveHitl.mockReset();
  });
  afterEach(cleanup);

  it("renders gate fields (frame enriches a pending summary entry) and posts approve", async () => {
    resolveHitl.mockResolvedValue(undefined);
    render(
      <HitLModal
        engagementId="eng_1"
        summary={summaryFor(gateFor("12", "(state preview)"))}
        events={[gateEvent]}
      />,
    );
    // The matching event frame's richer command preview wins over the
    // summary entry's placeholder.
    expect(screen.getByText(/msfconsole -x eternalblue/)).toBeTruthy();
    expect(screen.getByText("crashes host")).toBeTruthy();
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenCalledWith("eng_1", "12", true),
    );
  });

  it("renders nothing when a gate frame exists but the gate is resolved (no lockup)", () => {
    // The critical regression: event frames persist in the client history
    // after resolution — visibility must come from the state snapshot, or
    // the full-screen overlay would block the console forever.
    const { container } = render(
      <HitLModal engagementId="eng_1" summary={summaryFor()} events={[gateEvent]} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("dismisses the modal after a 409 (already resolved elsewhere)", async () => {
    resolveHitl.mockRejectedValue(new Error("already-resolved"));
    const { container } = render(
      <HitLModal
        engagementId="eng_1"
        summary={summaryFor(gateFor("12", "msfconsole -x eternalblue"))}
        events={[gateEvent]}
      />,
    );
    await userEvent.click(screen.getByText("Reject"));
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("renders nothing when no gate is pending", () => {
    const { container } = render(
      <HitLModal engagementId="eng_1" summary={summaryFor()} events={[]} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("falls back to the summary pending list when no frame exists (sticky)", () => {
    const pendingSummary = summaryFor(
      gateFor("7", "secretsdump.py domain/admin@10.0.0.9"),
    );
    render(
      <HitLModal engagementId="eng_1" summary={pendingSummary} events={[]} />,
    );
    expect(screen.getByText(/secretsdump\.py/)).toBeTruthy();
    expect(screen.getByText("Approve")).toBeTruthy();
  });

  it("shows the newest pending gate after a decision on the previous one", async () => {
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
      <HitLModal
        engagementId="eng_1"
        summary={summaryFor(gateFor("5", "nmap -sV 10.0.0.5"))}
        events={[gateA]}
      />,
    );
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenCalledWith("eng_1", "5", true),
    );
    // gate 5 is decided → dismissed (even while its frame is still around)
    await waitFor(() =>
      expect(screen.queryByText(/nmap -sV/)).toBeNull(),
    );

    // A second gate arrives: pending list now carries 12 (5 resolved) and
    // its frame supersedes the stale one for preview purposes.
    rerender(
      <HitLModal
        engagementId="eng_1"
        summary={summaryFor(gateFor("12", "crackmapexec smb 10.0.0.1"))}
        events={[gateB, gateA]}
      />,
    );
    expect(screen.getByText(/crackmapexec smb/)).toBeTruthy();
    expect(screen.queryByText(/nmap -sV/)).toBeNull();
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenLastCalledWith("eng_1", "12", true),
    );
    expect(resolveHitl).toHaveBeenCalledTimes(2);
  });

  it("disables Approve and Reject while a decision is in flight, then dismisses", async () => {
    let release: () => void = () => {};
    resolveHitl.mockImplementation(
      () => new Promise<void>((res) => { release = res; }),
    );
    const { container } = render(
      <HitLModal
        engagementId="eng_1"
        summary={summaryFor(gateFor("12", "msfconsole -x eternalblue"))}
        events={[gateEvent]}
      />,
    );
    await userEvent.click(screen.getByText("Approve"));
    expect(screen.getByText("Approve")).toBeDisabled();
    expect(screen.getByText("Reject")).toBeDisabled();
    await act(async () => { release(); });
    await waitFor(() => expect(container).toBeEmptyDOMElement());
    expect(resolveHitl).toHaveBeenCalledOnce();
  });
});
