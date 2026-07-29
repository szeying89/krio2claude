import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RunManifest } from "./RunManifest";
import * as client from "../api/client";

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>);
}

describe("RunManifest", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders run status and stage statuses once loaded", async () => {
    vi.spyOn(client, "getRun").mockResolvedValue({
      id: "run-1",
      status: "running",
      parent_run_id: null,
      project_name: "demo",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      stages: [
        {
          id: "s1",
          sequence_index: 0,
          name: "ingest",
          status: "complete",
          started_at: "2026-01-01T00:00:00Z",
          completed_at: "2026-01-01T00:00:01Z",
          error: null,
        },
      ],
    });

    renderWithClient(<RunManifest runId="run-1" />);

    await waitFor(() => expect(screen.getByTestId("run-status")).toHaveTextContent("running"));
    expect(screen.getByTestId("stage-ingest-status")).toHaveTextContent("complete");
  });

  it("shows an error state when the fetch fails", async () => {
    vi.spyOn(client, "getRun").mockRejectedValue(new Error("boom"));

    renderWithClient(<RunManifest runId="run-1" />);

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("boom"));
  });
});
