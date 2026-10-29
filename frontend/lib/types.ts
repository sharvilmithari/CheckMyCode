export interface Finding {
  id: string;
  rule_id: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  title: string;
  file_path: string;
  line_number?: number | null;
  explanation: string;
  impact: string;
  remediation: string;
  snippet?: string | null;
}

export interface ProjectProfile {
  project_name: string;
  total_files: number;
  inspected_files: number;
  approx_loc: number;
  languages: string[];
  frameworks: string[];
  manifests: string[];
  configs: string[];
}

export interface ReadinessScore {
  score: number;
  status: string;
  badge_color: string;
  badge_bg: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  methodology: string;
}

export interface ScanResponse {
  scan_id: string;
  project_name: string;
  profile: ProjectProfile;
  score_data: ReadinessScore;
  findings: Finding[];
  check_statuses: Record<string, string>;
}

export interface FeedbackPayload {
  project_name: string;
  overall_experience: string;
  results_useful: string;
  user_role: string;
  email?: string | null;
  improvement_notes?: string | null;
}

