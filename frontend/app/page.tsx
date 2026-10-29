import Link from "next/link";
import {
  ShieldAlert,
  KeyRound,
  FileCode2,
  PackageSearch,
  Container,
  ArrowRight,
  CheckCircle2,
  Lock,
} from "lucide-react";

export default function HomePage() {
  return (
    <div className="space-y-24 py-6">
      {/* ── HERO SECTION ── */}
      <section className="relative text-center max-w-3xl mx-auto space-y-6 pt-8 pb-4">
        {/* Subtle radial glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[300px] bg-primary/10 blur-[100px] -z-10 rounded-full pointer-events-none" />

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-text-primary leading-[1.15]">
          Your Code Works! <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary via-blue-400 to-accent">
            But Is It Ready to Ship?
          </span>
        </h1>

        <p className="text-base sm:text-lg text-text-secondary max-w-2xl mx-auto leading-relaxed">
          Find security vulnerabilities, exposed secrets, and risky configurations before they become deployment problems —{" "}
          <span className="text-primary font-semibold">for 100% free.</span>
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
          <Link
            href="/scan"
            className="w-full sm:w-auto px-7 py-3.5 rounded-lg bg-primary hover:bg-primary-hover text-white font-semibold text-base transition-all shadow-lg shadow-primary/25 flex items-center justify-center gap-2.5"
          >
            Scan My Project
            <ArrowRight className="w-4 h-4" />
          </Link>
          <a
            href="#how-it-works"
            className="w-full sm:w-auto px-6 py-3.5 rounded-lg bg-surface border border-border hover:border-text-secondary text-text-primary font-medium text-base transition-all"
          >
            Explore How It Works
          </a>
        </div>

        {/* Small honest preview illustration */}
        <div className="pt-8">
          <div className="rounded-xl border border-border bg-surface/80 p-4 text-left font-mono text-xs text-text-secondary max-w-xl mx-auto shadow-2xl backdrop-blur-sm">
            <div className="flex items-center justify-between pb-3 border-b border-border/80 text-[11px] text-text-muted">
              <span className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-critical inline-block" />
                <span>Example Finding Preview</span>
              </span>
              <span>RULE-ID: CMC-SEC-001</span>
            </div>
            <div className="pt-3 space-y-2">
              <div className="text-text-primary font-semibold flex items-center gap-2">
                <KeyRound className="w-3.5 h-3.5 text-critical" />
                <span>Hardcoded Cloud Provider Secret Detected</span>
              </div>
              <p className="text-text-muted text-[11px] leading-relaxed">
                Matches AWS Access Key Pattern in <code className="text-primary">backend/config.py:14</code>
              </p>
              <div className="p-2 rounded bg-background border border-border/60 text-accent text-[11px]">
                Recommended Fix: Move credential to environment variable or secret vault.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section id="how-it-works" className="space-y-10 scroll-mt-24">
        <div className="text-center space-y-2">
          <h2 className="text-xs font-mono font-bold tracking-widest text-primary uppercase">
            Workflow Overview
          </h2>
          <p className="text-2xl sm:text-3xl font-bold text-text-primary">
            How CheckMyCode Works
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center font-mono font-bold text-primary">
              01
            </div>
            <h3 className="text-lg font-semibold text-text-primary">1. Upload your project ZIP</h3>
            <p className="text-sm text-text-secondary leading-relaxed">
              Drop your source code archive into our secure uploader. The ZIP is extracted into an isolated volatile sandbox with strict path traversal protections.
            </p>
          </div>

          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center font-mono font-bold text-accent">
              02
            </div>
            <h3 className="text-lg font-semibold text-text-primary">2. CheckMyCode analyzes contents</h3>
            <p className="text-sm text-text-secondary leading-relaxed">
              Static analyzers inspect code patterns, configuration files, and manifest dependencies against bundled vulnerability advisories without executing code.
            </p>
          </div>

          <div className="p-6 rounded-xl border border-border bg-surface space-y-3">
            <div className="w-9 h-9 rounded-lg bg-medium/10 border border-medium/20 flex items-center justify-center font-mono font-bold text-medium">
              03
            </div>
            <h3 className="text-lg font-semibold text-text-primary">3. Review findings & recommended fixes</h3>
            <p className="text-sm text-text-secondary leading-relaxed">
              Inspect structured results with exact file locations, severity levels, and actionable remediation steps. Download standalone HTML or JSON compliance audits.
            </p>
          </div>
        </div>
      </section>

      {/* ── GENUINELY IMPLEMENTED CAPABILITIES ── */}
      <section id="capabilities" className="space-y-10">
        <div className="text-center space-y-2">
          <h2 className="text-xs font-mono font-bold tracking-widest text-accent uppercase">
            Inspection Capabilities
          </h2>
          <p className="text-2xl sm:text-3xl font-bold text-text-primary">
            Built-in Static Rule Scanners
          </p>
          <p className="text-sm text-text-secondary max-w-xl mx-auto">
            Only genuinely implemented detection checks are reported. No fabricated metrics or synthetic claims.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <div className="p-5 rounded-xl border border-border bg-surface-elevated space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-critical/10 text-critical flex items-center justify-center">
              <KeyRound className="w-4 h-4" />
            </div>
            <h4 className="text-base font-semibold text-text-primary">Secret Detection</h4>
            <p className="text-xs text-text-secondary leading-relaxed">
              Identifies high-entropy API keys, OpenAI tokens, AWS credentials, database URIs, and private RSA keys.
            </p>
          </div>

          <div className="p-5 rounded-xl border border-border bg-surface-elevated space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
              <FileCode2 className="w-4 h-4" />
            </div>
            <h4 className="text-base font-semibold text-text-primary">Code Security</h4>
            <p className="text-xs text-text-secondary leading-relaxed">
              AST checks for hazardous execution: eval(), exec(), shell=True subprocess calls, and disabled TLS verify.
            </p>
          </div>

          <div className="p-5 rounded-xl border border-border bg-surface-elevated space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-medium/10 text-medium flex items-center justify-center">
              <PackageSearch className="w-4 h-4" />
            </div>
            <h4 className="text-base font-semibold text-text-primary">Dependency Advisories</h4>
            <p className="text-xs text-text-secondary leading-relaxed">
              Evaluates requirements.txt and package.json against a bundled database of CVEs and unpinned packages.
            </p>
          </div>

          <div className="p-5 rounded-xl border border-border bg-surface-elevated space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-accent/10 text-accent flex items-center justify-center">
              <Container className="w-4 h-4" />
            </div>
            <h4 className="text-base font-semibold text-text-primary">Deployment Readiness</h4>
            <p className="text-xs text-text-secondary leading-relaxed">
              Checks Dockerfile root users, :latest tags, compose privileged flags, and committed live .env files.
            </p>
          </div>
        </div>
      </section>

      {/* ── PRIVACY & TRUST NOTICE ── */}
      <section className="p-6 sm:p-8 rounded-xl border border-border bg-surface/70 space-y-3">
        <div className="flex items-center gap-2 text-text-primary font-semibold">
          <Lock className="w-4 h-4 text-accent" />
          <span>Privacy & Security Architecture</span>
        </div>
        <p className="text-sm text-text-secondary leading-relaxed">
          CheckMyCode runs rule-based static analyzers locally. Your project archives are extracted into temporary folders that are deleted upon reset. Uploaded code is never executed, compiled, or sent to external AI providers.
        </p>
      </section>
    </div>
  );
}
