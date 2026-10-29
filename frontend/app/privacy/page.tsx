export default function PrivacyPage() {
  return (
    <div className="max-w-3xl mx-auto space-y-8 py-6 text-sm text-text-secondary leading-relaxed">
      <div className="space-y-1 pb-4 border-b border-border">
        <h1 className="text-3xl font-extrabold text-text-primary tracking-tight">
          Privacy Policy
        </h1>
        <p className="text-xs text-text-muted">Effective Date: October 2026</p>
      </div>

      <div className="space-y-6">
        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">1. Information You Submit</h2>
          <p>
            When utilizing CheckMyCode, you upload ZIP archives of project source code, dependency manifests (such as requirements.txt or package.json), and configuration files (such as Dockerfiles).
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">2. Archive Handling &amp; Lifecycle</h2>
          <p>Uploaded archives are processed strictly through local filesystem isolation:</p>
          <ul className="list-disc pl-5 space-y-1 text-xs">
            <li>Files are unpacked inside volatile temporary directories with validated path boundaries to prevent traversal attacks.</li>
            <li>Static analyzers perform read-only evaluations without code execution or compiler invocation.</li>
            <li>Once analysis is finalized, temporary directories and uncompressed source files are purged immediately from the host filesystem.</li>
          </ul>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">3. Data Storage &amp; Retention</h2>
          <p>
            CheckMyCode does not permanently store your project code, files, or intellectual property in a persistent database. Scan findings exist solely in active application memory and your browser session state.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">4. No External AI API Transmission</h2>
          <p>
            Your code is <strong>never</strong> transmitted to external artificial intelligence services, cloud language models, or third-party commercial data brokers. All static rules execute locally.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">5. Dependency Vulnerability Databases</h2>
          <p>
            Known vulnerability matching relies entirely on internal bundled advisory datasets within the scanner engine. No external network queries or dependency registries are contacted during inspection.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">6. Masking of Sensitive Tokens</h2>
          <p>
            When secrets (such as AWS keys or private tokens) are detected in code, CheckMyCode automatically masks sensitive character sequences in findings lists, visual displays, and downloaded reports to prevent accidental credential leakage.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">7. Post-Scan Feedback Submissions</h2>
          <p>
            If you voluntarily submit post-scan feedback, we collect your ratings, feedback comments, and optional email address. Feedback is stored locally in an application JSON log. Source code and project files are never attached to feedback.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">8. Tracking &amp; Telemetry</h2>
          <p>
            CheckMyCode does not use third-party tracking pixels, advertising cookies, or surveillance telemetry.
          </p>
        </section>
      </div>
    </div>
  );
}

