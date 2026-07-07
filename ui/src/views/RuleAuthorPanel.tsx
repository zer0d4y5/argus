import { useEffect, useState } from "react";
import { opsApi, ApiError, RuleTestResult, RuleSafetyIssue, SavedRule } from "../api";
import { Panel } from "../components";
import { useConfirm } from "../toast";

const inputClass =
  "w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500";
const labelClass = "mb-1 block text-xs uppercase text-gray-500 dark:text-gray-400";
const hintClass = "mt-1 text-xs text-gray-500 dark:text-gray-400";

const LANGUAGES = ["python", "javascript", "typescript", "go", "java", "csharp", "ruby", "php", "kotlin", "rust", "scala", "c", "swift"];

export function RuleAuthorPanel(): JSX.Element {
  const confirm = useConfirm();

  const [description, setDescription] = useState("");
  const [language, setLanguage] = useState("python");
  const [instruction, setInstruction] = useState("");
  const [rule, setRule] = useState("");
  const [draftModel, setDraftModel] = useState<string | null>(null);
  const [snippet, setSnippet] = useState("");
  const [test, setTest] = useState<RuleTestResult | null>(null);
  const [rules, setRules] = useState<SavedRule[]>([]);
  const [name, setName] = useState("");

  const [drafting, setDrafting] = useState(false);
  const [revising, setRevising] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);
  const [draftIssues, setDraftIssues] = useState<RuleSafetyIssue[]>([]);

  useEffect(() => {
    opsApi
      .listRules()
      .then((r) => setRules(r.rules))
      .catch(() => {});
  }, []);

  async function handleDraft() {
    setError(null);
    setOkMsg(null);
    setTest(null);
    setDrafting(true);
    try {
      const d = await opsApi.draftRule({ description, language });
      setRule(d.rule);
      setDraftModel(d.model);
      setDraftIssues(d.issues || []);
      if (!d.ready) {
        setError("Draft has safety issues; see below");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to draft rule");
    } finally {
      setDrafting(false);
    }
  }

  async function handleRevise() {
    if (!rule) return;
    setError(null);
    setOkMsg(null);
    setTest(null);
    setRevising(true);
    try {
      const d = await opsApi.draftRule({ description, language, existingRule: rule, instruction });
      setRule(d.rule);
      setDraftModel(d.model);
      setDraftIssues(d.issues || []);
      if (!d.ready) {
        setError("Draft has safety issues; see below");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to revise rule");
    } finally {
      setRevising(false);
      setInstruction("");
    }
  }

  async function handleTest() {
    if (!rule) return;
    setError(null);
    setOkMsg(null);
    setTesting(true);
    try {
      const result = await opsApi.testRule({ rule, snippet, language });
      setTest(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to test rule");
    } finally {
      setTesting(false);
    }
  }

  async function handleSave() {
    if (!rule || !name) return;
    setError(null);
    setOkMsg(null);
    setSaving(true);
    try {
      await opsApi.saveRule({ name, rule });
      setOkMsg("Saved and activated: " + name);
      setName("");
      const updated = await opsApi.listRules();
      setRules(updated.rules);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(ruleName: string) {
    const ok = await confirm({
      title: "Delete rule " + ruleName + "?",
      message: "This removes the saved rule and stops it running in scans.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    setError(null);
    setOkMsg(null);
    try {
      await opsApi.deleteRule(ruleName);
      const updated = await opsApi.listRules();
      setRules(updated.rules);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to delete rule");
    }
  }

  function renderIssues(issues: RuleSafetyIssue[]) {
    if (!issues || issues.length === 0) return null;
    return (
      <div className="mt-2 space-y-1">
        {issues.map((issue, i) => (
          <div key={i} className="flex items-start gap-2 text-xs">
            <span className={issue.blocking ? "text-red-600 dark:text-red-400" : "text-amber-600 dark:text-amber-400"}>
              {issue.blocking ? "✗" : "!"}
            </span>
            <span className="text-gray-700 dark:text-gray-300">{issue.message}</span>
          </div>
        ))}
      </div>
    );
  }

  return (
    <Panel title="AI-assisted rule authoring">
      <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">
        Describe a detection in plain language; a local model drafts a semgrep rule. Review, test it against an example, edit it freely, then save it as a custom rule. Nothing runs until you save.
      </p>

      <div className="space-y-4">
        {/* Describe */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Describe</div>
          <div className="space-y-4 mt-2">
            <div>
              <label className={labelClass}>Detection description</label>
              <textarea
                rows={3}
                placeholder="e.g. flag calls to eval() on a variable in Python"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className={`${inputClass} min-h-[72px] text-sm`}
              />
            </div>

            <div>
              <label className={labelClass}>Language</label>
              <select value={language} onChange={(e) => setLanguage(e.target.value)} className={inputClass}>
                {LANGUAGES.map((lang) => (
                  <option key={lang} value={lang}>
                    {lang}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <button
                type="button"
                onClick={handleDraft}
                disabled={drafting || !description.trim()}
                className="rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50"
              >
                {drafting ? "Drafting…" : "Draft with AI"}
              </button>
            </div>
          </div>
        </div>

        {/* Rule */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Rule</div>
          <div className="space-y-4 mt-2">
            {draftModel && (
              <span className="rounded border border-amber-400/50 px-1 text-[10px] text-amber-600 dark:text-amber-400">
                AI-generated ({draftModel})
              </span>
            )}

            <div>
              <textarea
                rows={12}
                value={rule}
                onChange={(e) => {
                  setRule(e.target.value);
                  setDraftModel(null);
                  setTest(null);
                }}
                className={`${inputClass} min-h-[220px] font-mono text-xs`}
              />
            </div>

            {renderIssues(draftIssues)}

            <div className="flex gap-3">
              <div className="flex-1">
                <label className={labelClass}>Revision instruction (optional)</label>
                <input
                  type="text"
                  placeholder="e.g. also match eval on request params"
                  value={instruction}
                  onChange={(e) => setInstruction(e.target.value)}
                  className={inputClass}
                />
              </div>
              <div className="flex items-end">
                <button
                  type="button"
                  onClick={handleRevise}
                  disabled={revising || !rule.trim()}
                  className="rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800"
                >
                  {revising ? "Revising…" : "Ask AI to revise"}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Test */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Test</div>
          <div className="space-y-4 mt-2">
            <div>
              <label className={labelClass}>Example snippet</label>
              <textarea
                rows={6}
                placeholder="paste an example the rule SHOULD match"
                value={snippet}
                onChange={(e) => setSnippet(e.target.value)}
                className={`${inputClass} min-h-[120px] font-mono text-xs`}
              />
            </div>

            <div>
              <button
                type="button"
                onClick={handleTest}
                disabled={testing || !rule.trim()}
                className="rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800"
              >
                {testing ? "Testing…" : "Validate & test"}
              </button>
            </div>

            {test && (
              <div className="mt-2 space-y-1 text-xs">
                {!test.valid && <div className="text-red-600 dark:text-red-400">Invalid rule: {test.validationError}</div>}
                {test.valid && <div>Safety: {test.safe ? "ok" : "issues"}</div>}
                {test.valid && (
                  <div>
                    {test.matched ? (
                      <span className="text-green-600 dark:text-green-400">
                        ✓ matched (lines {test.matches.map((m) => m.startLine).join(", ")})
                      </span>
                    ) : (
                      <span className="text-red-600 dark:text-red-400">✗ did not match</span>
                    )}
                  </div>
                )}
                {renderIssues(test.issues)}
              </div>
            )}
          </div>
        </div>

        {/* Save */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Save</div>
          <div className="space-y-4 mt-2">
            <div>
              <label className={labelClass}>Rule name</label>
              <input
                type="text"
                placeholder="my-rule-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className={inputClass}
              />
              <p className={hintClass}>Lowercase letters, digits, and dashes. Saving activates the rule (adds it to the custom rulesets).</p>
            </div>

            <button
              type="button"
              onClick={handleSave}
              disabled={saving || !rule.trim() || !name.trim()}
              className="rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save rule"}
            </button>
          </div>
        </div>

        {/* Saved rules */}
        <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Saved rules</div>
          <div className="space-y-2 mt-2">
            {rules.length === 0 && <p className={hintClass}>No custom rules saved yet.</p>}
            {rules.map((r) => (
              <div key={r.name} className="flex items-center justify-between rounded-md border border-gray-200 px-3 py-2 dark:border-gray-700">
                <div>
                  <span className="font-mono text-sm">{r.name}</span>
                  <span
                    className={`ml-2 rounded border px-1 text-[10px] ${
                      r.active ? "border-emerald-500 text-emerald-600 dark:text-emerald-400" : "border-gray-300 text-gray-500 dark:border-gray-600 dark:text-gray-400"
                    }`}
                  >
                    {r.active ? "active" : "inactive"}
                  </span>
                  <div className="text-[11px] text-gray-400">{r.path}</div>
                </div>
                <button
                  type="button"
                  onClick={() => handleDelete(r.name)}
                  className="text-[11px] text-red-600 hover:underline dark:text-red-400"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        </div>

        {okMsg && <div className="text-sm text-green-600 dark:text-green-400">{okMsg}</div>}
        {error && <div className="text-sm text-red-600 dark:text-red-400">{error}</div>}
      </div>
    </Panel>
  );
}
