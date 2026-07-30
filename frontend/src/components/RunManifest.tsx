import { useQuery } from "@tanstack/react-query";
import { getRun } from "../api/client";

export function RunManifest({ runId }: { runId: string }) {
  const { data: run, isLoading, error } = useQuery({
    queryKey: ["run", runId],
    queryFn: () => getRun(runId),
    refetchInterval: 2000,
  });

  if (isLoading) return <p>Loading run…</p>;
  if (error) return <p role="alert">Failed to load run: {(error as Error).message}</p>;
  if (!run) return null;

  return (
    <section aria-label="run manifest">
      <h2>
        Run {run.id} — <span data-testid="run-status">{run.status}</span>
      </h2>
      {run.project_name && <p>Project: {run.project_name}</p>}
      <ol>
        {run.stages.map((stage) => (
          <li key={stage.id}>
            {stage.name}: <span data-testid={`stage-${stage.name}-status`}>{stage.status}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
