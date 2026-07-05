import { FrameworkSummary } from "../api";
import { Panel } from "../components";

export function CompliancePanel({ compliance }: { compliance: FrameworkSummary[] }) {
  if (!compliance || compliance.length === 0) {
    return (
      <Panel title="Compliance posture">
        <p className="py-8 text-center text-sm text-gray-500 dark:text-gray-400">No compliance data.</p>
      </Panel>
    );
  }

  return (
    <Panel title="Compliance posture">
      <div className="flex flex-col divide-y divide-gray-100 dark:divide-gray-800">
        {compliance.map((fw) => {
          const rowTotal = fw.violatedControls + fw.cleanControls + fw.notAssessable;
          if (rowTotal === 0) return null;
          const pct = (n: number) => `${(n / rowTotal) * 100}%`;

          return (
            <div key={fw.id} className="py-3 first:pt-0 last:pb-0">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <div className="w-full shrink-0 sm:w-36">
                  <span className="text-sm font-semibold text-gray-900 dark:text-gray-100">{fw.id}</span>
                  <span className="ml-2 text-xs text-gray-400">v{fw.version}</span>
                </div>

                <div className="flex h-2.5 w-full flex-1 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
                  {fw.violatedControls > 0 && (
                    <div className="h-full flex-none bg-red-600" style={{ width: pct(fw.violatedControls) }} />
                  )}
                  {fw.cleanControls > 0 && (
                    <div className="h-full flex-none bg-emerald-600" style={{ width: pct(fw.cleanControls) }} />
                  )}
                  {fw.notAssessable > 0 && (
                    <div className="h-full flex-none bg-gray-400" style={{ width: pct(fw.notAssessable) }} />
                  )}
                </div>

                <div className="w-full shrink-0 text-right sm:w-auto">
                  <span className="text-xs tabular-nums text-gray-600 dark:text-gray-400">
                    <span className={fw.violatedControls > 0 ? "font-medium text-red-600 dark:text-red-400" : ""}>
                      {fw.violatedControls} violated
                    </span>
                    {" · "}
                    <span>{fw.cleanControls} clean</span>
                    {" · "}
                    <span>{fw.notAssessable} n/a</span>
                  </span>
                </div>
              </div>
              {fw.unmappedFindings > 0 && (
                <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                  {fw.unmappedFindings} finding(s) with no curated mapping
                </p>
              )}
            </div>
          );
        })}
      </div>

      <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
        Controls violated / no violations detected / not assessable by static scanning, per framework.
        Deterministic, hand-curated mapping — run `appsec comply` for the full gap report.
      </p>
    </Panel>
  );
}
