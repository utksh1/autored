import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import EngagementList from "./EngagementList";

const listEngagements = vi.fn();

vi.mock("../api", () => ({
  listEngagements: (...args: unknown[]) => listEngagements(...args),
}));

describe("EngagementList", () => {
  // Braced body on purpose: `() => listEngagements.mockReset()` would return the
  // mock, which vitest treats as a beforeEach cleanup hook and calls after the
  // test — producing an unhandled rejection when the last impl is mockRejectedValue.
  beforeEach(() => {
    listEngagements.mockReset();
  });

  it("renders rows and links running engagements", async () => {
    listEngagements.mockResolvedValue([
      { engagement_id: "eng_1", target: "10.0.0.1", phase: "exploit",
        started_at: "2026-09-27", operator: "op" },
    ]);
    render(
      <MemoryRouter>
        <EngagementList />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("eng_1")).toBeTruthy());
    const link = screen.getByRole("link", { name: "eng_1" });
    expect(link.getAttribute("href")).toBe("/engagements/eng_1");
  });

  it("shows an error card on API failure", async () => {
    listEngagements.mockRejectedValue(new Error("500"));
    render(
      <MemoryRouter>
        <EngagementList />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText(/500/)).toBeTruthy());
  });
});
