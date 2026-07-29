import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRun, getRun } from "./client";

describe("api client", () => {
  const fixtureRun = {
    id: "run-1",
    status: "queued",
    parent_run_id: null,
    project_name: "demo",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    stages: [
      {
        id: "stage-1",
        sequence_index: 0,
        name: "ingest",
        status: "pending",
        started_at: null,
        completed_at: null,
        error: null,
      },
    ],
  };

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        statusText: "OK",
        json: async () => fixtureRun,
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts stage names when creating a run", async () => {
    const run = await createRun(["ingest"], "demo");
    expect(run).toEqual(fixtureRun);
    const [url, init] = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain("/runs");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(init?.body as string)).toEqual({
      stage_names: ["ingest"],
      project_name: "demo",
    });
  });

  it("fetches a run manifest by id", async () => {
    const run = await getRun("run-1");
    expect(run.id).toBe("run-1");
    expect(run.stages).toHaveLength(1);
  });

  it("raises on a non-ok response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: async () => "run not found",
        json: async () => ({}),
      })),
    );
    await expect(getRun("missing")).rejects.toThrow("404");
  });
});
