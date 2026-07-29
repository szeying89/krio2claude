import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { createRun } from "./api/client";
import { RunManifest } from "./components/RunManifest";

const DEFAULT_STAGES = ["ingest", "enumerate", "risk", "assurance"];

function App() {
  const [runId, setRunId] = useState<string | null>(null);
  const createRunMutation = useMutation({
    mutationFn: () => createRun(DEFAULT_STAGES),
    onSuccess: (run) => setRunId(run.id),
  });

  return (
    <main>
      <h1>Ground-Truth Threat Modelling Platform</h1>
      <button
        type="button"
        onClick={() => createRunMutation.mutate()}
        disabled={createRunMutation.isPending}
      >
        {createRunMutation.isPending ? "Creating run…" : "Create run"}
      </button>
      {createRunMutation.isError && (
        <p role="alert">{(createRunMutation.error as Error).message}</p>
      )}
      {runId && <RunManifest runId={runId} />}
    </main>
  );
}

export default App;
