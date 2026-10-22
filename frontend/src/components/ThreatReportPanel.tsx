// Shared report-stage type definitions. The component that used to live
// here was merged into BehavioralAnalysisPanel.tsx's Reports accordion
// section (Stage1Content) to stop showing stage-1 data twice — this file now
// exists purely so the types below have one place to live.

export interface Stage1Data {
  malware_family: string;
  verdict: string;
  risk_score: number;
  severity: string;
  confidence: number;
  one_line_summary: string;
}

export interface Stage2Data {
  executive_summary: string;
  affected_systems: string[];
  business_impact: string;
  confidence: number;
}

export interface Stage3Data {
  mitre_techniques: Array<{ id: string; name: string; tactic: string; description: string }>;
  iocs: { domains: string[]; ips: string[]; files: string[]; registry_keys: string[] };
  attack_chain: string;
  confidence: number;
}

export interface Stage4Data {
  action_plan: Array<{ priority: number; action: string; urgency: string }>;
  yara_rule: string;
  iocs_to_block: string[];
  long_term_recommendations: string[];
  confidence: number;
}

export interface ReportStages {
  stage1?: Stage1Data;
  stage2?: Stage2Data;
  stage3?: Stage3Data;
  stage4?: Stage4Data;
}
