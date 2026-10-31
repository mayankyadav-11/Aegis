export type InputType = 'email' | 'sms' | 'url' | 'message' | 'text';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type Verdict = 'safe' | 'suspicious' | 'malicious';

export type Confidence = 'low' | 'medium' | 'high';

export type FindingCategory =
  | 'social_engineering'
  | 'url'
  | 'impersonation'
  | 'email_auth'
  | 'content'
  | 'anomaly';

export type FindingSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  category: FindingCategory;
  severity: FindingSeverity;
  evidence: string;
  explanation: string;
  recommended_action: string;
  source_module: string;
}

export type UrlReputation = 'unknown' | 'clean' | 'suspicious' | 'malicious';

export interface ExtractedUrl {
  url: string;
  domain: string;
  reputation: UrlReputation;
  flags: string[];
}

export interface LinkHop {
  hop: number;
  url: string;
  status: number;
  final: boolean;
  page_title: string | null;
  flags: string[];
}

export interface TextHighlight {
  start: number;
  end: number;
  severity: string;
  label: string;
}

export type BlockchainStatus = 'not_enabled' | 'pending' | 'anchored' | 'failed';

export interface SignalScores {
  nlp: number;
  url: number;
  sender: number;
  email_auth: number;
  context: number;
}

export interface ModelScores {
  url_classifier: number;
  text_classifier: number;
  anomaly: number;
}

export interface AnalysisResult {
  case_id: string;
  input_type: InputType;
  created_at: string;
  risk_score: number;
  risk_level: RiskLevel;
  verdict: Verdict;
  confidence: Confidence;
  signal_scores: SignalScores;
  model_scores: ModelScores;
  findings: Finding[];
  extracted_urls: ExtractedUrl[];
  link_trail: LinkHop[];
  highlights: TextHighlight[];
  unavailable_checks: string[];
  explanation: string;
  recommendations: string[];
  evidence_hash: string | null;
  blockchain_status: BlockchainStatus;
  transaction_hash: string | null;
}

export interface AnalyzeRequest {
  type: InputType;
  content: string;
  sender?: string;
  subject?: string;
}

export interface RedTeamVariantResult {
  technique: string;
  original_text: string;
  perturbed_text: string;
  before_score: number;
  after_score: number;
  evasion_successful: boolean;
}

export interface RedTeamResult {
  run_at: string;
  total_variants: number;
  resisted: number;
  bypassed: number;
  variants: RedTeamVariantResult[];
}

export interface ModelMetric {
  name: string;
  sample_size: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  latency_ms: number;
}

export interface MetricsResult {
  evaluated_at: string;
  models: ModelMetric[];
}

