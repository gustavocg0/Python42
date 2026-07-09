import type { Investigation } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { techniqueDescription, techniqueUrl } from "@/lib/mitre";
import { SeverityBadge } from "../Badges";

/**
 * Renders a deep-investigation result using the PERMANENT contract shape
 * (contract §9): the MVP stub returns empty arrays; the real engine fills
 * findings/timeline/evidence_graph/recommended_actions without breaking this
 * renderer. All strings render as plain text (SEC-31).
 */
export function InvestigationResult({ inv }: { inv: Investigation }) {
  return (
    <div className="card" data-testid="investigation-result">
      <p className="small muted">
        Run {formatDateTime(inv.requested_at)} · engine {inv.engine_version} ·
        status {inv.status}
        {inv.confidence !== null ? ` · confidence ${inv.confidence}` : ""}
      </p>
      {inv.is_stub ? (
        // ux spec §2.6 stub card labeling.
        <p className="banner banner-warning banner-inline">
          <strong>Preview.</strong> Full deep investigation is coming soon.
          This run confirmed your plan and quota.
        </p>
      ) : null}
      <p className="plain-text">{inv.summary}</p>

      {inv.findings.length > 0 ? (
        <>
          <h3>Findings</h3>
          <ul>
            {inv.findings.map((f) => (
              <li key={f.id}>
                <SeverityBadge severity={f.severity} /> <strong>{f.title}</strong>
                <p className="plain-text">{f.description}</p>
                {f.technique_ids.length > 0 ? (
                  <p className="small muted">
                    Techniques:{" "}
                    {f.technique_ids.map((t) => (
                      <a
                        key={t}
                        href={techniqueUrl(t)}
                        target="_blank"
                        rel="noreferrer noopener"
                        title={techniqueDescription(t)}
                      >
                        {t}{" "}
                      </a>
                    ))}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {inv.timeline.length > 0 ? (
        <>
          <h3>Timeline</h3>
          <ol>
            {inv.timeline.map((t, i) => (
              <li key={`${t.at}-${i}`}>
                <span className="muted small">{formatDateTime(t.at)}</span>{" "}
                <span className="plain-text">{t.description}</span>
              </li>
            ))}
          </ol>
        </>
      ) : null}

      {inv.evidence_graph.nodes.length > 0 ? (
        <>
          <h3>Evidence</h3>
          <ul>
            {inv.evidence_graph.nodes.map((n) => (
              <li key={n.id}>
                <span className="badge">{n.type}</span>{" "}
                <span className="plain-text">{n.label}</span>
              </li>
            ))}
          </ul>
          {inv.evidence_graph.edges.length > 0 ? (
            <ul className="small muted">
              {inv.evidence_graph.edges.map((e, i) => (
                <li key={i}>
                  {e.from} —{e.relation}→ {e.to}
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : null}

      {inv.recommended_actions.length > 0 ? (
        <>
          <h3>Recommended actions</h3>
          <ul>
            {inv.recommended_actions.map((a) => (
              <li key={a.id}>
                <strong>{a.title}</strong>
                <p className="plain-text">{a.description}</p>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}
