import {
  AnalysisResult,
  AnalyzeRequest,
  AuthStatus,
  CaseListResponse,
  EvidenceVerifyResult,
  MetricsResult,
  SystemHealth,
} from '@/types';

export const MOCK_CASES: AnalysisResult[] = [
  {
    case_id: 'AEG-2026-0001',
    input_type: 'sms',
    created_at: '2026-10-31T09:15:22.000Z',
    risk_score: 88,
    risk_level: 'high',
    verdict: 'malicious',
    confidence: 'high',
    signal_scores: {
      nlp: 86,
      url: 92,
      sender: 80,
      email_auth: 0,
      context: 75,
    },
    model_scores: {
      url_classifier: 0.94,
      text_classifier: 0.89,
      anomaly: 0.81,
    },
    findings: [
      {
        category: 'impersonation',
        severity: 'high',
        evidence: 'Claimed entity "SBI YONO" sent from generic numeric sender ID',
        explanation:
          'State Bank of India only dispatches transactional SMS via approved short headers (e.g., SBIBNK), not personal 10-digit mobile numbers.',
        recommended_action:
          'Do not respond or call back. Forward the SMS to 1909 (TRAI DND) or report to 1930.',
        source_module: 'brand_impersonation_engine',
      },
      {
        category: 'social_engineering',
        severity: 'high',
        evidence: 'Urgent threat: "account will be blocked today due to pending KYC"',
        explanation:
          'Artificial urgency forces panic to bypass critical reasoning. Banks do not instantaneously freeze accounts without prior written postal or authenticated in-app notice.',
        recommended_action: 'Verify your KYC status directly inside the official YONO SBI app only.',
        source_module: 'nlp_social_engineering',
      },
      {
        category: 'url',
        severity: 'high',
        evidence: 'Suspicious domain: sbi-kyc-update.top',
        explanation:
          'Uses a deceptive brand-hyphenated prefix on an untrusted .top generic top-level domain registered within the last 48 hours.',
        recommended_action: 'Never submit net banking credentials or OTPs on non-onlinesbi.sbi domains.',
        source_module: 'url_feature_classifier',
      },
    ],
    extracted_urls: [
      {
        url: 'http://sbi-kyc-update.top',
        domain: 'sbi-kyc-update.top',
        reputation: 'malicious',
        flags: ['typosquatting', 'newly_registered_domain', 'non_standard_tld', 'brand_in_subdomain'],
      },
    ],
    link_trail: [
      {
        hop: 1,
        url: 'http://sbi-kyc-update.top',
        status: 301,
        final: false,
        page_title: null,
        flags: ['http_unencrypted'],
      },
      {
        hop: 2,
        url: 'https://sbi-kyc-update.top/login.php',
        status: 200,
        final: true,
        page_title: 'State Bank of India - Quick KYC Verification',
        flags: ['credential_harvesting_form', 'otp_input_detected'],
      },
    ],
    highlights: [
      { start: 0, end: 28, severity: 'high', label: 'Impersonation & Threat' },
      { start: 42, end: 57, severity: 'medium', label: 'KYC Urgency Trigger' },
      { start: 67, end: 94, severity: 'high', label: 'Malicious Phishing URL' },
    ],
    unavailable_checks: [
      'Email authentication: not applicable for SMS channel',
      'SIM swap telecommunication telemetry: carrier API unavailable',
    ],
    explanation:
      'This SMS is a high-confidence banking credential harvesting scam imitating the State Bank of India. The message manufactures immediate panic regarding account deactivation to lure the victim into visiting a rogue phishing website designed to steal net-banking credentials and OTPs.',
    recommendations: [
      'Do not tap or click the link under any circumstances.',
      'Report the sender number to the National Cyber Crime Portal (cybercrime.gov.in) or dial 1930.',
      'Block the sender on your mobile handset immediately.',
    ],
    evidence_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    blockchain_status: 'anchored',
    transaction_hash: '0x8f2d59c6b8c9e4210a48bfa9382103f56e921865e9d3d0bc4c7b84f34c67912a',
  },
  {
    case_id: 'AEG-2026-0002',
    input_type: 'email',
    created_at: '2026-10-31T10:42:10.000Z',
    risk_score: 97,
    risk_level: 'critical',
    verdict: 'malicious',
    confidence: 'high',
    signal_scores: {
      nlp: 95,
      url: 99,
      sender: 98,
      email_auth: 96,
      context: 92,
    },
    model_scores: {
      url_classifier: 0.98,
      text_classifier: 0.96,
      anomaly: 0.94,
    },
    findings: [
      {
        category: 'email_auth',
        severity: 'critical',
        evidence: 'SPF: fail, DKIM: fail, DMARC: fail (p=reject breached via display spoofing)',
        explanation:
          'Sender headers claim "refunds@incometax.gov.in" but the connecting MTA IP is a residential VPS in Eastern Europe not authorised by the Ministry of Finance SPF record.',
        recommended_action: 'Quarantine and mark as phishing across corporate/mail gateway.',
        source_module: 'email_header_forensics',
      },
      {
        category: 'impersonation',
        severity: 'critical',
        evidence: 'Government of India - Income Tax Department emblem and typography clone',
        explanation:
          'Exact visual replication of government e-filing portal to deceive taxpayer into entering bank account details and debit card PIN.',
        recommended_action: 'Access your income tax portal only by navigating manually to incometax.gov.in.',
        source_module: 'brand_impersonation_engine',
      },
      {
        category: 'content',
        severity: 'critical',
        evidence: 'Unsolicited refund notification: INR 24,500 pending release',
        explanation:
          'Financial bait exploiting expectation of tax returns. The Income Tax Department credits refunds directly to pre-validated bank accounts via ECS/RTGS and never sends download links.',
        recommended_action: 'Delete immediately; never submit confidential banking data.',
        source_module: 'nlp_social_engineering',
      },
    ],
    extracted_urls: [
      {
        url: 'https://incometax-efiling-portal-verification.site/claim-refund',
        domain: 'incometax-efiling-portal-verification.site',
        reputation: 'malicious',
        flags: ['typosquatting', 'known_scam_infrastructure', 'credential_harvesting'],
      },
    ],
    link_trail: [
      {
        hop: 1,
        url: 'http://tinyurl.com/itax-refund-in',
        status: 302,
        final: false,
        page_title: null,
        flags: ['url_shortener_detected'],
      },
      {
        hop: 2,
        url: 'https://incometax-efiling-portal-verification.site/claim-refund',
        status: 200,
        final: true,
        page_title: 'e-Filing Anywhere Anytime - Tax Payer Verification',
        flags: ['fake_portal', 'card_pin_input_detected'],
      },
    ],
    highlights: [
      { start: 0, end: 45, severity: 'critical', label: 'Spoofed Government Header' },
      { start: 58, end: 110, severity: 'high', label: 'Financial Greed Lure' },
      { start: 125, end: 172, severity: 'critical', label: 'Deceptive Phishing Link' },
    ],
    unavailable_checks: [
      'Attachment detonation: zero-day sandbox analysis disabled on standard tier',
    ],
    explanation:
      'CRITICAL THREAT: Sophisticated spear-phishing campaign impersonating the Income Tax Department of India. Failed cryptographic mail signatures (SPF/DKIM/DMARC) prove direct identity spoofing designed to harvest debit card numbers, net-banking passwords, and OTP verification codes.',
    recommendations: [
      'Purge and block this email sender at the mail gateway.',
      'If any credentials or card numbers were entered, freeze your bank account and cards immediately.',
      'Lodge a formal cyber complaint on the 1930 helpline.',
    ],
    evidence_hash: '7d1a58c03bb7ef0a86d528b18f8e0257520b2d398935c13b2e3532cfd5efc071',
    blockchain_status: 'anchored',
    transaction_hash: '0x3c81e9d107a6d8924b819f2a019ef58d8c6b73a948e7150c9041b31278f24b83',
  },
  {
    case_id: 'AEG-2026-0003',
    input_type: 'email',
    created_at: '2026-10-31T11:05:45.000Z',
    risk_score: 6,
    risk_level: 'low',
    verdict: 'safe',
    confidence: 'high',
    signal_scores: {
      nlp: 5,
      url: 2,
      sender: 4,
      email_auth: 0,
      context: 3,
    },
    model_scores: {
      url_classifier: 0.03,
      text_classifier: 0.04,
      anomaly: 0.05,
    },
    findings: [
      {
        category: 'email_auth',
        severity: 'low',
        evidence: 'SPF: pass (google.com IP), DKIM: pass (domain: accounts.google.com), DMARC: pass',
        explanation: 'All cryptographic sender signatures are valid and originate from genuine Google infrastructure.',
        recommended_action: 'No action needed. Authentication parameters are fully verified.',
        source_module: 'email_header_forensics',
      },
      {
        category: 'url',
        severity: 'low',
        evidence: 'Destination domain: myaccount.google.com',
        explanation: 'Points to official Google Account Security settings via high-reputation TLS certificate.',
        recommended_action: 'Safe to proceed.',
        source_module: 'url_feature_classifier',
      },
    ],
    extracted_urls: [
      {
        url: 'https://myaccount.google.com/notifications',
        domain: 'myaccount.google.com',
        reputation: 'clean',
        flags: ['verified_official_domain', 'valid_hsts'],
      },
    ],
    link_trail: [
      {
        hop: 1,
        url: 'https://myaccount.google.com/notifications',
        status: 200,
        final: true,
        page_title: 'Google Account - Security Checkup',
        flags: ['safe'],
      },
    ],
    highlights: [],
    unavailable_checks: [],
    explanation:
      'This message has been authenticated as genuine. All domain reputation parameters, DNS security checks (SPF/DKIM/DMARC), and landing link structures belong cleanly to Google with no indications of social engineering or threat vector.',
    recommendations: [
      'Normal security alert from Google; review activity inside your Google Account if you performed recent sign-ins.',
    ],
    evidence_hash: 'a98f123c5e8b7d9124a908234be108912cfba541098231cdaef1092834bfa901',
    blockchain_status: 'anchored',
    transaction_hash: '0x192849ef2019842bf90128409128301982349012834019283091283091283091',
  },
];

// Runtime case memory store to preserve recent live analyses across navigation
const SESSION_CASES: Map<string, AnalysisResult> = new Map();

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, '') || 'http://localhost:8000';

const TOKEN_STORAGE_KEY = 'aegis_auth_token';
const SESSION_STORAGE_KEY = 'aegis_session_id';

export function getStoredToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token: string | null) {
  if (typeof window === 'undefined') return;
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

export function getStoredSessionId(): string {
  if (typeof window === 'undefined') return 'ses_client_init';
  let sid = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (!sid) {
    sid = 'ses_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    sessionStorage.setItem(SESSION_STORAGE_KEY, sid);
  }
  return sid;
}

export function setStoredSessionId(sid: string) {
  if (typeof window === 'undefined') return;
  sessionStorage.setItem(SESSION_STORAGE_KEY, sid);
}

export function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Session-ID': getStoredSessionId(),
  };
  const token = getStoredToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * Check backend API health and detector readiness.
 */
export async function checkHealth(): Promise<{
  online: boolean;
  health?: SystemHealth;
  error?: string;
}> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`${API_BASE_URL}/api/metrics`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
      cache: 'no-store',
    });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        online: false,
        error: `Backend responded with HTTP status ${res.status}`,
      };
    }

    const data: SystemHealth = await res.json();
    return { online: true, health: data };
  } catch (err: unknown) {
    const message =
      err instanceof Error
        ? err.name === 'AbortError'
          ? 'Connection timed out (backend not responding)'
          : err.message
        : 'Cannot connect to backend';
    return { online: false, error: message };
  }
}

/**
 * Execute real backend analysis across URL, Text, SMS, or Email endpoints.
 */
export async function analyze(data: AnalyzeRequest): Promise<AnalysisResult> {
  let endpoint = '/api/analyze/text';
  let bodyPayload: Record<string, unknown> = {};

  const cleanContent = data.content.trim();

  switch (data.type) {
    case 'url': {
      endpoint = '/api/analyze/url';
      bodyPayload = { url: cleanContent };
      break;
    }
    case 'sms': {
      endpoint = '/api/analyze/sms';
      bodyPayload = {
        content: cleanContent,
        input_type: 'sms',
        sender: data.sender?.trim() || null,
      };
      break;
    }
    case 'email': {
      endpoint = '/api/analyze/email';
      bodyPayload = {
        content: cleanContent,
        sender: data.sender?.trim() || null,
        subject: data.subject?.trim() || null,
      };
      break;
    }
    case 'text':
    case 'message':
    default: {
      endpoint = '/api/analyze/text';
      bodyPayload = {
        content: cleanContent,
        input_type: data.type === 'message' ? 'message' : 'text',
        sender: data.sender?.trim() || null,
      };
      break;
    }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 35000);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...getAuthHeaders(),
    };

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(bodyPayload),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    // Sync session ID if returned by server
    const serverSessionId = response.headers.get('X-Session-ID');
    if (serverSessionId) {
      setStoredSessionId(serverSessionId);
    }

    if (!response.ok) {
      let errorDetail = `Backend error (${response.status})`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          if (Array.isArray(errorJson.detail)) {
            errorDetail = errorJson.detail.map((d: { msg?: string }) => d.msg || '').join(', ');
          } else if (typeof errorJson.detail === 'string') {
            errorDetail = errorJson.detail;
          }
        }
      } catch {
        // Fall back
      }
      throw new Error(errorDetail);
    }

    const result: AnalysisResult = await response.json();

    if (result && result.case_id) {
      SESSION_CASES.set(result.case_id.toLowerCase(), result);
    }

    return result;
  } catch (err: unknown) {
    if (err instanceof TypeError && err.message.toLowerCase().includes('fetch')) {
      throw new Error(
        `AEGIS backend unreachable at ${API_BASE_URL}. Ensure FastAPI is running on port 8000.`
      );
    }
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('Analysis timed out after 35 seconds.');
    }
    throw err;
  }
}

/**
 * Upload and analyze file payload (.eml, .pdf, or screenshot image).
 */
export async function analyzeFile(formData: FormData): Promise<AnalysisResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 45000);

    const headers = {
      Accept: 'application/json',
      ...getAuthHeaders(),
    };

    const response = await fetch(`${API_BASE_URL}/api/analyze/file`, {
      method: 'POST',
      headers,
      body: formData,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const serverSessionId = response.headers.get('X-Session-ID');
    if (serverSessionId) {
      setStoredSessionId(serverSessionId);
    }

    if (!response.ok) {
      let errorDetail = `Upload analysis failed (${response.status})`;
      try {
        const errJson = await response.json();
        if (errJson.detail) {
          errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
        }
      } catch {
        // Fall back
      }
      throw new Error(errorDetail);
    }

    const result: AnalysisResult = await response.json();
    if (result && result.case_id) {
      SESSION_CASES.set(result.case_id.toLowerCase(), result);
    }
    return result;
  } catch (err: unknown) {
    if (err instanceof TypeError && err.message.toLowerCase().includes('fetch')) {
      throw new Error(`AEGIS backend unreachable at ${API_BASE_URL}.`);
    }
    throw err;
  }
}

/**
 * Enterprise Authentication APIs
 */
export async function enterpriseLogin(email: string, password: string) {
  const res = await fetch(`${API_BASE_URL}/api/metrics`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Login failed.');
  }
  const data = await res.json();
  setStoredToken(data.token);
  return data;
}

export async function enterpriseLogout() {
  setStoredToken(null);
  await fetch(`${API_BASE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: { Accept: 'application/json', ...getAuthHeaders() },
  }).catch(() => {});
}

export async function getAuthStatus(): Promise<AuthStatus> {
  const token = getStoredToken();
  if (!token) {
    return {
      authenticated: false,
      mode: 'session',
      session_id: getStoredSessionId(),
    };
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/metrics`, {
      method: 'GET',
      headers: { Accept: 'application/json', ...getAuthHeaders() },
    });
    if (!res.ok) {
      setStoredToken(null);
      return {
        authenticated: false,
        mode: 'session',
        session_id: getStoredSessionId(),
      };
    }
    const data = await res.json();
    return {
      authenticated: data.authenticated,
      mode: data.mode,
      user: data.authenticated
        ? {
            id: data.user_id,
            org_id: data.org_id,
            org_name: data.org_name,
            email: data.email,
            role: data.role,
          }
        : undefined,
      session_id: data.session_id || getStoredSessionId(),
    };
  } catch {
    return {
      authenticated: false,
      mode: 'session',
      session_id: getStoredSessionId(),
    };
  }
}

/**
 * Dual-Mode Case Listing (Enterprise persistent or Session ephemeral)
 */
export async function listCases(params?: {
  query?: string;
  input_type?: string;
  verdict?: string;
  risk_level?: string;
  limit?: number;
  offset?: number;
}): Promise<CaseListResponse> {
  const token = getStoredToken();
  const isEnterprise = Boolean(token);
  const endpoint = isEnterprise ? '/api/cases' : '/api/session/cases';

  const queryParams = new URLSearchParams();
  if (params?.query) queryParams.set('query', params.query);
  if (params?.input_type) queryParams.set('input_type', params.input_type);
  if (params?.verdict) queryParams.set('verdict', params.verdict);
  if (params?.risk_level) queryParams.set('risk_level', params.risk_level);
  if (params?.limit) queryParams.set('limit', String(params.limit));
  if (params?.offset) queryParams.set('offset', String(params.offset));

  const url = `${API_BASE_URL}${endpoint}${queryParams.toString() ? '?' + queryParams.toString() : ''}`;

  try {
    const res = await fetch(`${API_BASE_URL}/api/metrics`, {
      method: 'GET',
      headers: { Accept: 'application/json', ...getAuthHeaders() },
    });

    if (!res.ok) {
      if (res.status === 401 && isEnterprise) {
        setStoredToken(null);
      }
      throw new Error(`Failed to list cases (${res.status})`);
    }

    const data: CaseListResponse = await res.json();
    return data;
  } catch {
    // Fall back to in-memory session cases
    const sessionList = Array.from(SESSION_CASES.values());
    return {
      total: sessionList.length,
      cases: sessionList,
      limit: 50,
      offset: 0,
      mode: isEnterprise ? 'enterprise' : 'session',
    };
  }
}

export async function clearSession(): Promise<void> {
  SESSION_CASES.clear();
  try {
    await fetch(`${API_BASE_URL}/api/session`, {
      method: 'DELETE',
      headers: { Accept: 'application/json', ...getAuthHeaders() },
    });
  } catch {
    // Ignore offline errors
  }
}

/**
 * Download PDF Forensic Report
 */
export async function downloadReport(caseId: string, isEnterprise = false): Promise<void> {
  const endpoint = isEnterprise ? `/api/cases/${caseId}/report` : `/api/session/cases/${caseId}/report`;
  const res = await fetch(`${API_BASE_URL}/api/metrics`, {
    method: 'GET',
    headers: { ...getAuthHeaders() },
  });

  if (!res.ok) {
    throw new Error(`Could not generate PDF report (${res.status})`);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = `AEGIS-Forensic-Report-${caseId}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(blobUrl);
}

/**
 * Verify Digital Evidence SHA-256 Digest
 */
export async function verifyCaseEvidence(caseId: string, isEnterprise = false): Promise<EvidenceVerifyResult> {
  const endpoint = isEnterprise ? `/api/cases/${caseId}/verify` : `/api/session/cases/${caseId}/verify`;
  const res = await fetch(`${API_BASE_URL}/api/metrics`, {
    method: 'POST',
    headers: { Accept: 'application/json', ...getAuthHeaders() },
  });

  if (!res.ok) {
    throw new Error(`Evidence verification failed (${res.status})`);
  }

  return await res.json();
}

export async function getCases(): Promise<AnalysisResult[]> {
  const list = await listCases();
  if (list && list.cases.length > 0) {
    return list.cases;
  }
  const sessionList = Array.from(SESSION_CASES.values());
  const seenIds = new Set(sessionList.map((c) => c.case_id.toLowerCase()));
  const mocks = MOCK_CASES.filter((c) => !seenIds.has(c.case_id.toLowerCase()));
  return [...sessionList, ...mocks];
}

export async function getCase(id: string): Promise<AnalysisResult | null> {
  const normalizedId = id.toLowerCase();
  if (SESSION_CASES.has(normalizedId)) {
    return SESSION_CASES.get(normalizedId)!;
  }

  // Try fetching from API
  try {
    const token = getStoredToken();
    const endpoint = token ? `/api/cases/${id}` : `/api/session/cases/${id}`;
    const res = await fetch(`${API_BASE_URL}/api/metrics`, {
      method: 'GET',
      headers: { Accept: 'application/json', ...getAuthHeaders() },
    });
    if (res.ok) {
      const data = await res.json();
      return data;
    }
  } catch {
    // Fall back to mock
  }

  const found = MOCK_CASES.find((c) => c.case_id.toLowerCase() === normalizedId);
  return found || null;
}


export async function getMetrics(): Promise<MetricsResult> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/metrics`, {
      method: 'GET',
      headers: { Accept: 'application/json', ...getAuthHeaders() },
    });
    if (res.ok) {
      const data: MetricsResult = await res.json();
      return { ...data, is_demo: false };
    }
  } catch {
    // Fall back to mock
  }

  await new Promise((resolve) => setTimeout(resolve, 300));
  return {
    evaluated_at: '2026-10-31T08:00:00.000Z',
    is_demo: true,
    models: [
      {
        name: 'URL Lexical Classifier (Random Forest + Gradient Boosting)',
        sample_size: 15420,
        precision: 0.968,
        recall: 0.954,
        f1: 0.961,
        false_positive_rate: 0.012,
        latency_ms: 8.4,
      },
      {
        name: 'NLP Phishing & Social Engineering (TF-IDF + Logistic Regression)',
        sample_size: 8950,
        precision: 0.942,
        recall: 0.938,
        f1: 0.94,
        false_positive_rate: 0.021,
        latency_ms: 12.1,
      },
      {
        name: 'Indian SMS & Hinglish Targeted Model',
        sample_size: 450,
        precision: 0.925,
        recall: 0.912,
        f1: 0.918,
        false_positive_rate: 0.035,
        latency_ms: 9.7,
      },
      {
        name: 'Contextual Anomaly Detector (Isolation Forest)',
        sample_size: 12000,
        precision: 0.908,
        recall: 0.895,
        f1: 0.901,
        false_positive_rate: 0.028,
        latency_ms: 5.2,
      },
    ],
  };
}

