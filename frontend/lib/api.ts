import { ScanResponse, FeedbackPayload } from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function uploadAndScanProject(
  file: File,
  prefs: { secrets: boolean; code_sec: boolean; deps: boolean; config: boolean }
): Promise<ScanResponse> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("secrets", String(prefs.secrets));
  formData.append("code_sec", String(prefs.code_sec));
  formData.append("deps", String(prefs.deps));
  formData.append("config", String(prefs.config));

  const res = await fetch(`${API_BASE_URL}/api/scans`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Scan request failed" }));
    throw new Error(errorData.detail || `Scan failed with status ${res.status}`);
  }

  return res.json();
}

export async function getScanById(scanId: string): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE_URL}/api/scans/${scanId}`);
  if (!res.ok) {
    throw new Error(`Failed to load scan with ID ${scanId}`);
  }
  return res.json();
}

export function getReportDownloadUrl(scanId: string, format: "pdf" | "html" | "json" = "pdf"): string {
  return `${API_BASE_URL}/api/scans/${scanId}/report?format=${format}`;
}

export async function submitFeedback(payload: FeedbackPayload): Promise<boolean> {
  const res = await fetch(`${API_BASE_URL}/api/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error("Failed to submit feedback");
  }

  return true;
}

