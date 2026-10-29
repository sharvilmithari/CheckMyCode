"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  UploadCloud,
  FileArchive,
  AlertCircle,
  Loader2,
  Check,
  ShieldCheck,
  KeyRound,
  FileCode2,
  PackageSearch,
  Container,
  Sparkles,
} from "lucide-react";
import { uploadAndScanProject } from "@/lib/api";

export default function ScanPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Scan preferences
  const [prefs, setPrefs] = useState({
    secrets: true,
    code_sec: true,
    deps: true,
    config: true,
  });

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    setError(null);

    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles && droppedFiles.length > 0) {
      validateAndSetFile(droppedFiles[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (f: File) => {
    if (!f.name.toLowerCase().endsWith(".zip")) {
      setError("Only ZIP archives (.zip) are supported.");
      return;
    }
    if (f.size > 50 * 1024 * 1024) {
      setError("File exceeds the maximum 50 MB size limit.");
      return;
    }
    setFile(f);
  };

  const handleStartScan = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);

    try {
      const result = await uploadAndScanProject(file, prefs);
      // Store in sessionStorage so results page can immediately display it
      sessionStorage.setItem("cmc_latest_scan", JSON.stringify(result));
      router.push(`/results?scan_id=${result.scan_id}`);
    } catch (err: any) {
      let msg = err.message || "An unexpected error occurred during scan.";
      if (msg.includes("Failed to fetch") || msg.includes("NetworkError")) {
        msg = "Cannot connect to the FastAPI backend service. Please ensure the backend is running on http://127.0.0.1:8000.";
      }
      setError(msg);
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 py-4">
      <div className="space-y-1">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-text-primary">
          Scan Your Project
        </h1>
        <p className="text-sm text-text-secondary">
          Upload a ZIP archive of your source code to run static security checks.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Upload Column */}
        <div className="md:col-span-2 space-y-6">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition-all ${
              isDragging
                ? "border-primary bg-primary/5"
                : "border-border bg-surface hover:border-border/80"
            }`}
          >
            <input
              type="file"
              id="zip-upload"
              accept=".zip"
              className="hidden"
              onChange={handleFileChange}
              disabled={loading}
            />

            {!file ? (
              <label
                htmlFor="zip-upload"
                className="cursor-pointer flex flex-col items-center justify-center space-y-3"
              >
                <div className="w-14 h-14 rounded-full bg-surface-elevated border border-border flex items-center justify-center text-primary shadow-inner">
                  <UploadCloud className="w-7 h-7" />
                </div>
                <div className="space-y-1">
                  <span className="text-base font-semibold text-text-primary">
                    Drop your project ZIP here
                  </span>
                  <p className="text-xs text-text-secondary">
                    or click to browse your computer (Max 50 MB)
                  </p>
                </div>
                <span className="mt-2 inline-block px-4 py-2 rounded-lg bg-surface-elevated border border-border hover:border-primary text-xs font-medium text-text-primary transition-colors">
                  Choose Project ZIP
                </span>
              </label>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-center gap-3 p-4 rounded-lg bg-surface-elevated border border-border max-w-md mx-auto">
                  <FileArchive className="w-8 h-8 text-primary shrink-0" />
                  <div className="text-left overflow-hidden">
                    <p className="text-sm font-semibold text-text-primary truncate">
                      {file.name}
                    </p>
                    <p className="text-xs text-text-muted">
                      {(file.size / (1024 * 1024)).toFixed(2)} MB
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-center gap-3">
                  <label
                    htmlFor="zip-upload"
                    className="text-xs text-text-muted hover:text-text-primary cursor-pointer underline underline-offset-4"
                  >
                    Replace File
                  </label>
                  <span className="text-text-muted text-xs">&middot;</span>
                  <button
                    type="button"
                    onClick={() => setFile(null)}
                    disabled={loading}
                    className="text-xs text-critical hover:underline underline-offset-4"
                  >
                    Remove
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Error notice */}
          {error && (
            <div className="flex items-start gap-2.5 p-3.5 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
              <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Active Scanner Toggles */}
          <div className="p-5 rounded-xl border border-border bg-surface space-y-3">
            <h3 className="text-xs font-mono font-bold tracking-wider uppercase text-text-secondary">
              Active Security Scanners
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <label className="flex items-center gap-2.5 cursor-pointer text-text-secondary hover:text-text-primary">
                <input
                  type="checkbox"
                  checked={prefs.secrets}
                  onChange={(e) => setPrefs({ ...prefs, secrets: e.target.checked })}
                  className="rounded border-border text-primary focus:ring-0 bg-background"
                />
                <span className="flex items-center gap-1.5 text-xs">
                  <KeyRound className="w-3.5 h-3.5 text-critical" />
                  Secret Detection
                </span>
              </label>

              <label className="flex items-center gap-2.5 cursor-pointer text-text-secondary hover:text-text-primary">
                <input
                  type="checkbox"
                  checked={prefs.code_sec}
                  onChange={(e) => setPrefs({ ...prefs, code_sec: e.target.checked })}
                  className="rounded border-border text-primary focus:ring-0 bg-background"
                />
                <span className="flex items-center gap-1.5 text-xs">
                  <FileCode2 className="w-3.5 h-3.5 text-primary" />
                  Code Security Analysis
                </span>
              </label>

              <label className="flex items-center gap-2.5 cursor-pointer text-text-secondary hover:text-text-primary">
                <input
                  type="checkbox"
                  checked={prefs.deps}
                  onChange={(e) => setPrefs({ ...prefs, deps: e.target.checked })}
                  className="rounded border-border text-primary focus:ring-0 bg-background"
                />
                <span className="flex items-center gap-1.5 text-xs">
                  <PackageSearch className="w-3.5 h-3.5 text-medium" />
                  Dependency CVE Advisories
                </span>
              </label>

              <label className="flex items-center gap-2.5 cursor-pointer text-text-secondary hover:text-text-primary">
                <input
                  type="checkbox"
                  checked={prefs.config}
                  onChange={(e) => setPrefs({ ...prefs, config: e.target.checked })}
                  className="rounded border-border text-primary focus:ring-0 bg-background"
                />
                <span className="flex items-center gap-1.5 text-xs">
                  <Container className="w-3.5 h-3.5 text-accent" />
                  Deployment Readiness
                </span>
              </label>
            </div>
          </div>

          {/* Submit Button */}
          <button
            onClick={handleStartScan}
            disabled={!file || loading}
            className={`w-full py-3.5 px-6 rounded-lg font-semibold text-sm transition-all flex items-center justify-center gap-2 shadow-lg ${
              !file || loading
                ? "bg-surface-elevated text-text-muted cursor-not-allowed border border-border"
                : "bg-primary hover:bg-primary-hover text-white shadow-primary/25 cursor-pointer"
            }`}
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing project in isolated sandbox...
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                Run Security Scan
              </>
            )}
          </button>
        </div>

        {/* Sidebar Info Column */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl border border-border bg-surface-elevated space-y-3">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-accent" />
              Supported Codebases
            </h3>
            <ul className="text-xs text-text-secondary space-y-2 list-disc pl-4">
              <li>Python (scripts, requirements.txt, setup.py)</li>
              <li>JavaScript & TypeScript (package.json)</li>
              <li>Dockerfiles & Docker Compose manifests</li>
              <li>Configuration files (.env, yaml, toml)</li>
            </ul>
          </div>

          <div className="p-5 rounded-xl border border-border bg-surface space-y-2.5">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-text-secondary">
              Execution Safety
            </h4>
            <p className="text-xs text-text-secondary leading-relaxed">
              Uploaded files are strictly inspected via AST and static regular expression checks. No scripts are executed, compiled, or evaluated on the server.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
