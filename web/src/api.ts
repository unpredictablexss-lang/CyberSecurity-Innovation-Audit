export const terminal = new Set([
  "completed",
  "completed_with_limitations",
  "blocked",
  "failed",
  "cancelled",
  "interrupted",
  "timed_out",
]);
export async function api(path: string, body?: unknown): Promise<any> {
  const r = await fetch(
    "/api/v1" + path,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-OHScanner-Client": "workbench-v1",
          },
          body: JSON.stringify(body),
        },
  );
  if (!r.ok) {
    const e = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(
      typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail),
    );
  }
  return r.json();
}
export const artifact = (id: string, kind: string) =>
  "/api/v1/scans/" + id + "/artifacts/" + kind;
