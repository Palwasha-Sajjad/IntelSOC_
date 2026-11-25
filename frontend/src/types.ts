export type Role = 'viewer' | 'analyst' | 'administrator';
export interface User {
  user_id: string;
  username: string;
  email: string;
  role: Role;
  status: 'active';
  expires_at: string;
}
export interface DashboardSummary {
  generated_at: string;
  total_events: number;
  events_last_24h: number;
  total_alerts: number;
  open_alerts: number;
  total_incidents: number;
  open_incidents: number;
  registered_devices: number;
  active_registrations: number;
  pending_registrations: number;
  revoked_registrations: number;
  high_severity_alerts: number;
  normal_risk: number;
  suspicious_risk: number;
  malicious_risk: number;
  unassessed_alerts: number;
}
export interface AlertSummary {
  alert_id: string;
  title: string;
  hostname: string | null;
  severity: string;
  status: string;
  created_at: string;
  overall_score: number | null;
  classification: string | null;
}
