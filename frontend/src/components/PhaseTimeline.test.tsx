import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PhaseTimeline from "./PhaseTimeline";

describe("PhaseTimeline", () => {
  it("marks completed phases and the active one", () => {
    render(<PhaseTimeline phase="exploit" />);
    expect(screen.getByText(/✓ recon/)).toBeTruthy();
    expect(screen.getByText("exploit")).toBeTruthy();
  });
});
