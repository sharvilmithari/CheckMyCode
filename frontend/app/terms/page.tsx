export default function TermsPage() {
  return (
    <div className="max-w-3xl mx-auto space-y-8 py-6 text-sm text-text-secondary leading-relaxed">
      <div className="space-y-1 pb-4 border-b border-border">
        <h1 className="text-3xl font-extrabold text-text-primary tracking-tight">
          Terms &amp; Conditions
        </h1>
        <p className="text-xs text-text-muted">Effective Date: October 2026</p>
      </div>

      <div className="space-y-6">
        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">1. Acceptance of Terms</h2>
          <p>
            By accessing or using CheckMyCode (&quot;Service&quot;), you agree to be bound by these Terms and Conditions. If you do not agree with any part of these terms, you may not use the Service.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">2. Purpose and Scope of CheckMyCode</h2>
          <p>
            CheckMyCode provides automated, rule-based static security checks and deployment-readiness assessments for source code archives. The Service is intended for development and educational review purposes.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">3. User Responsibility for Uploaded Projects</h2>
          <p>
            You retain full ownership of all source code, configurations, and files submitted to CheckMyCode. You are solely responsible for ensuring your submissions do not violate applicable laws or proprietary licenses.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">4. Requirement of Authorization to Scan Code</h2>
          <p>
            You warrant that you own or have obtained all necessary permissions, licenses, and authorizations from the legal rightsholders to upload, analyze, and scan any code or archives submitted to the Service.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">5. Acceptable Use Policy</h2>
          <p>You agree not to use CheckMyCode to:</p>
          <ul className="list-disc pl-5 space-y-1 text-xs">
            <li>Submit maliciously crafted archives designed to disrupt or exploit host infrastructure (such as zip bombs or directory traversal attacks).</li>
            <li>Attempt to reverse engineer or bypass application sandbox boundaries.</li>
            <li>Scan proprietary third-party code without documented authorization.</li>
          </ul>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">6. Limitations of Automated Security Scanning</h2>
          <p>
            CheckMyCode relies on static pattern matching, abstract syntax trees, and bundled vulnerability databases. It does not execute your code or observe dynamic runtime environments. Automated scanning cannot detect every flaw and may produce false positives and false negatives.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">7. No Guarantee of Complete Detection</h2>
          <p>
            CheckMyCode makes no guarantee or warranty that it will identify every security vulnerability or bug in your project. A clean scan score means only that no issues matched our currently implemented detection rules.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">8. User Responsibility Prior to Deployment</h2>
          <p>
            You are exclusively responsible for independently auditing, testing, and verifying all findings, recommended fixes, and configuration adjustments before promoting code to production.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">9. Service Availability &amp; Potential Errors</h2>
          <p>
            The Service is provided on an &quot;as is&quot; and &quot;as available&quot; basis without warranties of uninterrupted uptime or universal compatibility with non-standard project layouts.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">10. Limitation of Liability</h2>
          <p>
            To the maximum extent permitted by applicable law, CheckMyCode, its developers, and contributors shall not be liable for any direct, indirect, incidental, or consequential damages resulting from the use or inability to use the Service.
          </p>
        </section>

        <section className="space-y-2">
          <h2 className="text-base font-bold text-text-primary">11. Changes to Terms</h2>
          <p>
            We reserve the right to modify these Terms and Conditions at any time. Continued use of the platform constitutes acceptance of revised terms.
          </p>
        </section>
      </div>
    </div>
  );
}

