import {
  AnalysisResult,
  AnalyzeRequest,
  MetricsResult,
  RedTeamResult,
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

export async function analyze(data: AnalyzeRequest): Promise<AnalysisResult> {
  // Simulate network latency
  await new Promise((resolve) => setTimeout(resolve, 600));

  // Determine which mock case to return based on heuristic or content
  const contentLower = data.content.toLowerCase();
  if (contentLower.includes('kyc') || contentLower.includes('sbi') || data.type === 'sms') {
    return {
      ...MOCK_CASES[0],
      case_id: `AEG-2026-${Math.floor(1000 + Math.random() * 9000)}`,
      input_type: data.type,
      created_at: new Date().toISOString(),
    };
  } else if (contentLower.includes('refund') || contentLower.includes('tax') || data.type === 'email') {
    return {
      ...MOCK_CASES[1],
      case_id: `AEG-2026-${Math.floor(1000 + Math.random() * 9000)}`,
      input_type: data.type,
      created_at: new Date().toISOString(),
    };
  }

  return {
    ...MOCK_CASES[2],
    case_id: `AEG-2026-${Math.floor(1000 + Math.random() * 9000)}`,
    input_type: data.type,
    created_at: new Date().toISOString(),
  };
}

export async function getCases(): Promise<AnalysisResult[]> {
  await new Promise((resolve) => setTimeout(resolve, 200));
  return MOCK_CASES;
}

export async function getCase(id: string): Promise<AnalysisResult | null> {
  await new Promise((resolve) => setTimeout(resolve, 200));
  const found = MOCK_CASES.find((c) => c.case_id.toLowerCase() === id.toLowerCase());
  return found || MOCK_CASES[0];
}

export async function runRedTeam(): Promise<RedTeamResult> {
  await new Promise((resolve) => setTimeout(resolve, 800));
  return {
    run_at: new Date().toISOString(),
    total_variants: 5,
    resisted: 5,
    bypassed: 0,
    variants: [
      {
        technique: 'Homoglyph attack (Cyrillic a/o in SBI bank name)',
        original_text: 'Dear SBI customer, update KYC immediately',
        perturbed_text: 'Deаr SBI custоmer, updаte KYC immediаtely',
        before_score: 88,
        after_score: 89,
        evasion_successful: false,
      },
      {
        technique: 'Zero-width space injection in sensitive terms',
        original_text: 'Verify your OTP to prevent account suspension',
        perturbed_text: 'Verify your O​T​P to prevent account sus​pen​sion',
        before_score: 92,
        after_score: 91,
        evasion_successful: false,
      },
      {
        technique: 'Leetspeak character substitution',
        original_text: 'Urgent: Click here to claim your cash refund',
        perturbed_text: 'Urg3nt: Cl1ck h3r3 t0 cl41m y0ur c4sh r3fund',
        before_score: 85,
        after_score: 87,
        evasion_successful: false,
      },
      {
        technique: 'URL hex encoding & IP address obfuscation',
        original_text: 'http://sbi-update.top/login',
        perturbed_text: 'http://%73%62%69%2d%75%70%64%61%74%65%2e%74%6f%70/%6c%6f%67%69%6e',
        before_score: 94,
        after_score: 94,
        evasion_successful: false,
      },
      {
        technique: 'Hinglish urgent threat phrasing',
        original_text: 'Aapka bank account aaj raat 12 baje band ho jayega KYC karo',
        perturbed_text: 'Apka b@nk acnt aj rat 12 bje bnd hojyga kyc kro',
        before_score: 90,
        after_score: 88,
        evasion_successful: false,
      },
    ],
  };
}

export async function getMetrics(): Promise<MetricsResult> {
  await new Promise((resolve) => setTimeout(resolve, 300));
  return {
    evaluated_at: '2026-10-31T08:00:00.000Z',
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

