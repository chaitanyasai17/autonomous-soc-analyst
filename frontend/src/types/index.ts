// TypeScript types matching FastAPI backend schema

export type UserRole = "super_admin" | "admin" | "soc_manager" | "analyst" | "viewer";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "in_progress" | "resolved" | "closed" | "false_positive";
export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "closed";
export type ProcessingStatus = "pending" | "processing" | "completed" | "failed";
export type LogSource = "firewall" | "ids_ips" | "endpoint" | "server" | "application" | "cloud" | "network_device" | "other";

export interface User {
  id: string;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface SecurityLog {
  id: string;
  filename: string;
  original_filename: string;
  file_size: number;
  file_type: string;
  log_source: LogSource;
  processing_status: ProcessingStatus;
  uploaded_by_id: string;
  upload_time: string;
  event_count?: number;
}

export interface ParsedLog {
  id: string;
  security_log_id: string;
  timestamp: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  username?: string;
  hostname?: string;
  event_id?: string;
  event_type: string;
  severity: RiskLevel;
  protocol?: string;
  action?: string;
  message?: string;
  raw_log: string;
  created_at: string;
}

export interface SigmaRule {
  id: string;
  title: string;
  category?: string;
  level: RiskLevel;
  status?: string;
  description?: string;
  tags?: string[];
  detection?: any;
  fields?: string[];
  enabled: boolean;
}

export interface SigmaDetection {
  id: string;
  parsed_log_id: string;
  matched_rule: string;
  rule_title: string;
  rule_category?: string;
  rule_tags?: string[];
  severity: RiskLevel;
  confidence: number;
  matched_fields?: Array<{ field: string; value: string; selection: string }>;
  detection_timestamp: string;
  created_at: string;
}

export interface MitreTechnique {
  id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  description?: string;
  reference_url?: string;
  detection_count?: number;
}

export interface MitreTactic {
  id: string;
  short_name: string;
  name: string;
  description: string;
  techniques_count: number;
  active_detections_count: number;
}

export interface MitreMatrixColumn {
  tactic: MitreTactic;
  techniques: MitreTechnique[];
}

export interface MitreMatrixData {
  tactics: MitreMatrixColumn[];
  total_tactics: number;
  total_techniques: number;
  total_detections_mapped: number;
}

export interface RiskFactor {
  name: string;
  impact: number;
  detail: string;
}

export interface RiskAssessment {
  id: string;
  sigma_detection_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  calculated_at: string;
  explanation?: string;
  contributing_factors?: RiskFactor[];
}

export interface Alert {
  id: string;
  title: string;
  description?: string;
  severity: RiskLevel;
  status: AlertStatus;
  resolved_at?: string;
  risk_assessment_id?: string;
  incident_id?: string;
  assigned_to_id?: string;
  created_at: string;
  risk_score?: number;
  assigned_username?: string;
}

export interface Incident {
  id: string;
  incident_number: string;
  title?: string;
  description?: string;
  priority: RiskLevel;
  status: IncidentStatus;
  opened_at: string;
  closed_at?: string;
  owner_id?: string;
  owner_username?: string;
  alert_count: number;
  alerts?: Alert[];
}

export type Detection = SigmaDetection;

export interface AIThreatAnalysis {
  threat_summary: string;
  attack_narrative: string;
  confidence: number;
  false_positive_likelihood: "low" | "medium" | "high";
  false_positive_rationale?: string;
  recommended_actions: string[];
  indicators_of_compromise: Array<{ type: string; value: string; description?: string }>;
  mitre_alignment: string[];
  provider_used: string;
}

export interface Report {
  id: string;
  report_name: string;
  report_type: "pdf" | "csv";
  generated_at: string;
  file_path: string;
  generated_by_id?: string;
}

export interface Notification {
  id: string;
  recipient_id: string;
  notification_type: string;
  title: string;
  message: string;
  is_read: boolean;
  sent_at: string;
}

export interface TopVulnerableEndpoint {
  target_url: string;
  findings_count: number;
  highest_severity: string;
}

export interface DashboardSummary {
  total_alerts: number;
  critical_alerts: number;
  open_incidents: number;
  average_risk_score: number;
  total_logs_uploaded: number;
  severity_distribution: Record<string, number>;
  incident_status_distribution: Record<string, number>;
  recent_alerts: Alert[];
  top_tactics: MitreTactic[];
  total_detections?: number;
  active_alerts?: number;
  at_risk_endpoints?: number;
  total_endpoints?: number;
  online_endpoints?: number;
  web_posture_score?: number;
  active_web_findings?: number;
  targets_monitored?: number;
  top_vulnerable_endpoints?: TopVulnerableEndpoint[];
}

export interface Endpoint {
  id: string;
  hostname: string;
  ip_address?: string;
  mac_address?: string;
  operating_system: string;
  os_version?: string;
  agent_version: string;
  status: string;
  risk_level: RiskLevel;
  owner_id: string;
  owner_username?: string;
  is_isolated: boolean;
  isolation_reason?: string;
  last_seen: string;
  registered_at: string;
  tags?: string[];
  event_count?: number;
  detection_count?: number;
  alert_count?: number;
}

export interface IOCRecord {
  id: string;
  ioc_type: string;
  value: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  related_alert_id?: string;
  related_incident_id?: string;
  description?: string;
  tags?: string[];
}

export interface IncidentTimelineEvent {
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
  source: string;
  metadata?: Record<string, any>;
}

export interface IncidentTimelineResponse {
  incident_id: string;
  incident_number: string;
  total_events?: number;
  events?: IncidentTimelineEvent[];
  timeline?: IncidentTimelineEvent[];
  summary?: {
    total_events: number;
    first_event_at?: string;
    last_event_at?: string;
    earliest_telemetry_gap_seconds?: number;
  };
}

export interface SOCEngineHealth {
  name: string;
  status: "ONLINE" | "DEGRADED" | "OFFLINE";
  latency_ms: number;
  details?: Record<string, any>;
  message?: string;
}

export interface SOCHealthResponse {
  status: "HEALTHY" | "DEGRADED" | "CRITICAL";
  timestamp: string;
  engines: SOCEngineHealth[];
  summary: {
    total_engines: number;
    online_count: number;
    degraded_count: number;
    offline_count: number;
  };
}

