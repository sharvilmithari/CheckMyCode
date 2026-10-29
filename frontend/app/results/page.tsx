"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Download,
  FileCode,
  FileText,
  Search,
  Filter,
  CheckCircle2,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { ScanResponse, Finding } from "@/lib/types";
import { getScanById, getReportDownloadUrl, submitFeedback } from "@/lib/api";

function ResultsContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const scanId = searchParams.get("scan_id");

  const [scanData, setScanData] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // Feedback state
  const [fbExperience, setFbExperience] = useState("Excellent");
  const [fbUseful, setFbUseful] = useState("Yes");
  const [fbRole, setFbRole] = useState("Developer");
  const [fbEmail, setFbEmail] = useState("");
  const [fbNotes, setFbNotes] = useState("");
  const [fbSubmitted, setFbSubmitted] = useState(false);
  const [fbLoading, setFbLoading] = useState(false);

  useEffect(() => {
    // 1. Try reading from sessionStorage for instant load
    const cached = sessionStorage.getItem("cmc_latest_scan");
    if (cached) {
      try {
        const parsed: ScanResponse = JSON.parse(cached);
        if (!scanId || parsed.scan_id === scanId) {
          setScanData(parsed);
          setLoading(false);
          // auto expand first finding
          if (parsed.findings.length > 0) {
            setExpandedFindings({ [parsed.findings[0].id]: true });
          }
          return;
        }
      } catch (e) {
        // Fall back to API
      }
    }

    // 2. Fetch from backend if scanId exists
    if (scanId) {
      getScanById(scanId)
        .then((res) => {
          setScanData(res);
          setLoading(false);
          if (res.findings.length > 0) {
            setExpandedFindings({ [res.findings[0].id]: true });
          }
        })
        .catch((err) => {
          setError(err.message || "Failed to load scan results");
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, [scanId]);

  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleFeedbackSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanData) return;
    setFbLoading(true);

    try {
      await submitFeedback({
        project_name: scanData.project_name,
        overall_experience: fbExperience,
        results_useful: fbUseful,
        user_role: fbRole,
        email: fbEmail.trim() || null,
        improvement_notes: fbNotes.trim() || null,
      });
      setFbSubmitted(true);
    } catch (err) {
      alert("Failed to submit feedback. Please try again.");
    } finally {
      setFbLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="py-24 text-center space-y-4">
        <RefreshCw className="w-8 h-8 text-primary animate-spin mx-auto" />
        <p className="text-text-secondary text-sm">Loading security audit findings...</p>
      </div>
    );
  }

  if (error || !scanData) {
    return (
      <div className="py-16 text-center space-y-4 max-w-md mx-auto">
        <div className="w-12 h-12 rounded-full bg-critical/10 text-critical flex items-center justify-center mx-auto">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-xl font-bold text-text-primary">No Scan Available</h2>
        <p className="text-sm text-text-secondary">
          {error || "No active scan was found. Start a new scan to analyze your project code."}
        </p>
        <Link
          href="/scan"
          className="inline-block px-5 py-2.5 rounded-lg bg-primary text-white font-medium text-sm hover:bg-primary-hover transition-colors"
        >
          Go to Scanner
        </Link>
      </div>
    );
  }

  const { profile, score_data, findings, check_statuses } = scanData;

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.severity.toUpperCase() !== severityFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchPath = f.file_path.toLowerCase().includes(q);
      const matchRule = f.rule_id.toLowerCase().includes(q);
      return matchTitle || matchPath || matchRule;
    }
    return true;
  });

  return (
    <div className="space-y-8 py-2">
      {/* ── TOP HEADER ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-border">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-primary font-bold tracking-wider uppercase mb-1">
            <span>Audit Findings</span>
            <span>&middot;</span>
            <span>CheckMyCode Engine</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-text-primary flex items-center gap-3">
            <span>{profile.project_name}</span>
            <span className="text-xs px-2.5 py-1 rounded-full bg-surface-elevated border border-border text-text-secondary font-mono">
              {profile.inspected_files} files inspected
            </span>
          </h1>
          <p className="text-xs text-text-muted mt-1">
            ~{profile.approx_loc.toLocaleString()} LOC &middot; Languages:{" "}
            {profile.languages.length > 0 ? profile.languages.join(", ") : "None detected"}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <Link
            href="/scan"
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:border-primary text-text-primary text-xs font-semibold transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            New Scan
          </Link>
          <a
            href={getReportDownloadUrl(scanData.scan_id, "pdf")}
            download
            className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold transition-all shadow-md shadow-primary/20 flex items-center gap-1.5"
            title="Download multi-page executive & technical PDF audit report"
          >
            <FileText className="w-3.5 h-3.5" />
            Download PDF Report
          </a>
          <a
            href={getReportDownloadUrl(scanData.scan_id, "html")}
            download
            className="px-3 py-2 rounded-lg bg-surface border border-border hover:border-text-secondary text-text-secondary hover:text-text-primary text-xs font-medium transition-colors flex items-center gap-1.5"
            title="Download standalone HTML report"
          >
            <Download className="w-3.5 h-3.5" />
            HTML
          </a>
          <a
            href={getReportDownloadUrl(scanData.scan_id, "json")}
            download
            className="px-3 py-2 rounded-lg bg-surface border border-border hover:border-text-secondary text-text-secondary hover:text-text-primary text-xs font-medium transition-colors flex items-center gap-1.5"
            title="Download structured JSON report"
          >
            <FileCode className="w-3.5 h-3.5 text-accent" />
            JSON
          </a>
        </div>
      </div>

      {/* ── SCORE & SEVERITY KPI CARDS ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Score Ring / Card */}
        <div className="p-5 rounded-xl border border-border bg-surface flex flex-col justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-text-muted">
            Readiness Score
          </span>
          <div className="flex items-baseline gap-2 my-2">
            <span
              className="text-4xl font-extrabold font-mono"
              style={{ color: score_data.badge_color }}
            >
              {Math.round(score_data.score)}
            </span>
            <span className="text-sm text-text-muted font-mono">/ 100</span>
          </div>
          <span
            className="text-[11px] font-semibold px-2 py-0.5 rounded-full inline-block w-fit"
            style={{
              backgroundColor: score_data.badge_bg,
              color: score_data.badge_color,
            }}
          >
            {score_data.status}
          </span>
        </div>

        {/* Critical */}
        <div className="p-5 rounded-xl border border-border bg-surface flex flex-col justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-critical">
            Critical
          </span>
          <span className="text-3xl font-extrabold font-mono text-text-primary my-1">
            {score_data.critical_count}
          </span>
          <span className="text-[11px] text-text-muted">-25 pts deduction each</span>
        </div>

        {/* High */}
        <div className="p-5 rounded-xl border border-border bg-surface flex flex-col justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-high">
            High Risk
          </span>
          <span className="text-3xl font-extrabold font-mono text-text-primary my-1">
            {score_data.high_count}
          </span>
          <span className="text-[11px] text-text-muted">-12 pts deduction each</span>
        </div>

        {/* Medium */}
        <div className="p-5 rounded-xl border border-border bg-surface flex flex-col justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-medium">
            Medium
          </span>
          <span className="text-3xl font-extrabold font-mono text-text-primary my-1">
            {score_data.medium_count}
          </span>
          <span className="text-[11px] text-text-muted">-5 pts deduction each</span>
        </div>

        {/* Low / Info */}
        <div className="p-5 rounded-xl border border-border bg-surface flex flex-col justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-low">
            Low / Info
          </span>
          <span className="text-3xl font-extrabold font-mono text-text-primary my-1">
            {score_data.low_count}
          </span>
          <span className="text-[11px] text-text-muted">-2 pts deduction each</span>
        </div>
      </div>

      {/* ── SCAN STATUS BADGES ── */}
      <div className="p-4 rounded-xl border border-border bg-surface/60 flex flex-wrap items-center gap-6 text-xs text-text-secondary">
        {Object.entries(check_statuses).map(([name, status]) => (
          <div key={name} className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                status.includes("Skipped") ? "bg-text-muted" : "bg-accent shadow-sm shadow-accent"
              }`}
            />
            <span className="font-medium text-text-primary">{name}:</span>
            <span className="text-text-muted">{status}</span>
          </div>
        ))}
      </div>

      {/* ── FINDINGS FILTER & SEARCH ── */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          {/* Severity Tabs */}
          <div className="flex items-center gap-1.5 p-1 bg-surface rounded-lg border border-border overflow-x-auto">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                  severityFilter === sev
                    ? "bg-primary text-white"
                    : "text-text-secondary hover:text-text-primary hover:bg-surface-elevated"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Search bar */}
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              placeholder="Search findings or files..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface border border-border text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary"
            />
          </div>
        </div>

        <div className="text-xs text-text-muted">
          Showing <strong className="text-text-primary">{filteredFindings.length}</strong> of{" "}
          {findings.length} findings
        </div>

        {/* ── FINDINGS LIST ── */}
        {filteredFindings.length === 0 ? (
          <div className="p-12 rounded-xl border border-border bg-surface text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-accent mx-auto" />
            <h3 className="text-base font-semibold text-text-primary">No Findings Match</h3>
            <p className="text-xs text-text-muted max-w-sm mx-auto">
              No security findings match the active severity or search query filters.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredFindings.map((f) => {
              const isOpen = !!expandedFindings[f.id];
              const sevBadgeColor =
                f.severity === "Critical"
                  ? "bg-critical/15 text-critical border-critical/30"
                  : f.severity === "High"
                  ? "bg-high/15 text-high border-high/30"
                  : f.severity === "Medium"
                  ? "bg-medium/15 text-medium border-medium/30"
                  : "bg-low/15 text-low border-low/30";

              return (
                <div
                  key={f.id}
                  className="rounded-xl border border-border bg-surface overflow-hidden transition-all"
                >
                  {/* Finding Title Header */}
                  <div
                    onClick={() => toggleFinding(f.id)}
                    className="p-4 sm:p-5 flex items-start sm:items-center justify-between gap-4 cursor-pointer hover:bg-surface-elevated/40 transition-colors"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded border shrink-0 ${sevBadgeColor}`}
                      >
                        {f.severity}
                      </span>
                      <span className="font-semibold text-sm text-text-primary">{f.title}</span>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className="font-mono text-xs text-text-muted hidden md:inline">
                        {f.file_path}
                        {f.line_number ? `:${f.line_number}` : ""}
                      </span>
                      {isOpen ? (
                        <ChevronUp className="w-4 h-4 text-text-muted" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-text-muted" />
                      )}
                    </div>
                  </div>

                  {/* Finding Expanded Detail */}
                  {isOpen && (
                    <div className="px-4 pb-5 sm:px-5 sm:pb-5 pt-1 border-t border-border/80 space-y-4 text-xs">
                      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-text-muted pt-2">
                        <span className="px-2 py-0.5 rounded bg-background border border-border">
                          {f.rule_id}
                        </span>
                        <span>&middot;</span>
                        <span>Category: {f.category}</span>
                        <span>&middot;</span>
                        <span className="text-primary">
                          Location: {f.file_path}
                          {f.line_number ? `:${f.line_number}` : ""}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1.5 p-3 rounded-lg bg-background-secondary border border-border">
                          <strong className="text-text-primary text-xs block">Explanation</strong>
                          <p className="text-text-secondary leading-relaxed">{f.explanation}</p>
                        </div>
                        <div className="space-y-1.5 p-3 rounded-lg bg-background-secondary border border-border">
                          <strong className="text-text-primary text-xs block">Why It Matters</strong>
                          <p className="text-text-secondary leading-relaxed">{f.impact}</p>
                        </div>
                      </div>

                      {/* Code snippet if present */}
                      {f.snippet && (
                        <div className="space-y-1">
                          <span className="text-[11px] font-mono text-text-muted uppercase">
                            Detected Code Fragment
                          </span>
                          <pre className="p-3 rounded-lg bg-background border border-border font-mono text-xs text-text-primary overflow-x-auto">
                            <code>{f.snippet}</code>
                          </pre>
                        </div>
                      )}

                      {/* Remediation guidance */}
                      <div className="p-3 rounded-lg bg-accent/5 border border-accent/20 text-accent space-y-1">
                        <strong className="text-xs font-semibold block text-text-primary">
                          Recommended Remediation
                        </strong>
                        <p className="leading-relaxed">{f.remediation}</p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── EXPORT DOWNLOADS ── */}
      <div className="p-6 rounded-xl border border-border bg-surface-elevated space-y-4">
        <div className="space-y-1">
          <h3 className="text-base font-bold text-text-primary flex items-center gap-2">
            <Download className="w-4 h-4 text-primary" />
            Export Audit Artifacts
          </h3>
          <p className="text-xs text-text-secondary max-w-xl">
            Download self-contained security audit reports for pull request attachments, stakeholder sign-off, or CI/CD pipelines.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <a
            href={getReportDownloadUrl(scanData.scan_id, "pdf")}
            download
            className="px-5 py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold transition-all shadow-md shadow-primary/25 flex items-center gap-2"
          >
            <FileText className="w-4 h-4" />
            Download PDF Report (Executive &amp; Technical)
          </a>
          <a
            href={getReportDownloadUrl(scanData.scan_id, "html")}
            download
            className="px-4 py-2.5 rounded-lg bg-surface border border-border hover:border-text-secondary text-text-primary text-xs font-semibold transition-all flex items-center gap-2"
          >
            <Download className="w-4 h-4 text-text-muted" />
            Download HTML Report
          </a>
          <a
            href={getReportDownloadUrl(scanData.scan_id, "json")}
            download
            className="px-4 py-2.5 rounded-lg bg-surface border border-border hover:border-text-secondary text-text-primary text-xs font-semibold transition-all flex items-center gap-2"
          >
            <FileCode className="w-4 h-4 text-accent" />
            Download JSON Report
          </a>
        </div>
      </div>

      {/* ── POST-SCAN FEEDBACK FORM ── */}
      <div className="p-6 rounded-xl border border-border bg-surface space-y-5">
        <div>
          <h3 className="text-lg font-bold text-text-primary">Help us improve CheckMyCode</h3>
          <p className="text-xs text-text-secondary mt-0.5">
            Was this scan useful? Tell us what worked and what we can improve.
          </p>
        </div>

        {fbSubmitted ? (
          <div className="p-4 rounded-lg bg-accent/10 border border-accent/30 text-accent text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            <span>Thank you! Your feedback has been recorded and saved successfully.</span>
          </div>
        ) : (
          <form onSubmit={handleFeedbackSubmit} className="space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-text-secondary font-medium">1. Overall experience</label>
                <select
                  value={fbExperience}
                  onChange={(e) => setFbExperience(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-background border border-border text-text-primary focus:outline-none focus:border-primary"
                >
                  <option>Excellent</option>
                  <option>Good</option>
                  <option>Average</option>
                  <option>Poor</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-text-secondary font-medium">2. Were the results useful?</label>
                <select
                  value={fbUseful}
                  onChange={(e) => setFbUseful(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-background border border-border text-text-primary focus:outline-none focus:border-primary"
                >
                  <option>Yes</option>
                  <option>Partly</option>
                  <option>No</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-text-secondary font-medium">3. What best describes you?</label>
                <select
                  value={fbRole}
                  onChange={(e) => setFbRole(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-background border border-border text-text-primary focus:outline-none focus:border-primary"
                >
                  <option>Developer</option>
                  <option>Student</option>
                  <option>Freelancer</option>
                  <option>Other</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-text-secondary font-medium">
                  4. Email address (Optional)
                </label>
                <input
                  type="email"
                  placeholder="you@domain.com (only if you want a response)"
                  value={fbEmail}
                  onChange={(e) => setFbEmail(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-background border border-border text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-text-secondary font-medium">
                5. What should we improve? (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="Tell us what checks were most helpful or what you'd like added..."
                value={fbNotes}
                onChange={(e) => setFbNotes(e.target.value)}
                className="w-full p-2.5 rounded-lg bg-background border border-border text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary resize-none"
              />
            </div>

            <button
              type="submit"
              disabled={fbLoading}
              className="px-5 py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-white font-semibold transition-all shadow-md shadow-primary/20 disabled:opacity-50"
            >
              {fbLoading ? "Submitting..." : "Submit Feedback"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default function ResultsPage() {
  return (
    <Suspense
      fallback={
        <div className="py-24 text-center text-text-muted text-sm">
          Loading scan results...
        </div>
      }
    >
      <ResultsContent />
    </Suspense>
  );
}

