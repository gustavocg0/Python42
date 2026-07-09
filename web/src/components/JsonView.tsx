/**
 * Raw JSON display. Rendering via text nodes only — React escapes everything;
 * no dangerouslySetInnerHTML anywhere in this app (SEC-31).
 */
export function JsonView({ data, label }: { data: unknown; label?: string }) {
  let text: string;
  try {
    text = JSON.stringify(data, null, 2);
  } catch {
    text = String(data);
  }
  return (
    <pre className="json-view" aria-label={label ?? "Raw data"}>
      {text}
    </pre>
  );
}
