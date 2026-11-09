import crypto from 'crypto';
import { Alert, ApiKeyRecord, DashboardSummary, ScanResult, ThreatReport, WatchlistDomain } from './types';
import { getScanStats } from './db';

// Global in-memory storage singleton for demo / server persistence
declare global {
  // eslint-disable-next-line no-var
  var __TRUSTIFY_DB: {
    scans: Map<string, ScanResult>;
    threatReports: Map<string, ThreatReport>;
    alerts: Map<string, Alert>;
    apiKeys: Map<string, ApiKeyRecord>;
    watchlist: Map<string, WatchlistDomain>;
    userVotes: Map<string, number>; // `${userId}:${reportId}` -> 1 | -1
    userProfile: {
      name: string;
      email: string;
      role: string;
      reputation: number;
    };
  } | undefined;
}

function initDb() {
  if (global.__TRUSTIFY_DB) {
    // Clear out any previously seeded demo alerts and demo scans
    global.__TRUSTIFY_DB.alerts.delete('alert-01');
    global.__TRUSTIFY_DB.alerts.delete('alert-02');
    global.__TRUSTIFY_DB.alerts.delete('alert-03');
    global.__TRUSTIFY_DB.scans.delete('scan-paypa1-01');
    global.__TRUSTIFY_DB.scans.delete('scan-example-01');
    global.__TRUSTIFY_DB.scans.delete('scan-badssl-expired');
    return global.__TRUSTIFY_DB;
  }

  const scans = new Map<string, ScanResult>();
  const threatReports = new Map<string, ThreatReport>();
  const alerts = new Map<string, Alert>();
  const apiKeys = new Map<string, ApiKeyRecord>();
  const watchlist = new Map<string, WatchlistDomain>();
  const userVotes = new Map<string, number>();

  // 1. Initial Scans (starts empty; populated dynamically by real scans)
  const initialScans: ScanResult[] = [];

  // 2. Seed Threat Intelligence Reports
  const initialReports: ThreatReport[] = [
    {
      id: 'rep-001',
      url: 'https://paypa1-secure-login.com/auth/verify',
      domain: 'paypa1-secure-login.com',
      category: 'phishing',
      description: 'SMS phishing link sent to users in India claiming their PayPal account is temporarily restricted.',
      status: 'verified',
      upvotes: 42,
      downvotes: 1,
      reporterReputation: 88,
      createdAt: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
    },
    {
      id: 'rep-002',
      url: 'https://sbi-card-kyc-update.top/login.html',
      domain: 'sbi-card-kyc-update.top',
      category: 'fake_payment',
      description: 'Fraudulent bank KYC portal requesting PAN, Aadhaar, and debit card PIN.',
      status: 'verified',
      upvotes: 68,
      downvotes: 0,
      reporterReputation: 95,
      createdAt: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
    },
    {
      id: 'rep-003',
      url: 'https://amazon-order-delivery-track.click/refund',
      domain: 'amazon-order-delivery-track.click',
      category: 'impersonation',
      description: 'Fake delivery tracking page harvesting Amazon login credentials and CVV.',
      status: 'verified',
      upvotes: 29,
      downvotes: 2,
      reporterReputation: 74,
      createdAt: new Date(Date.now() - 12 * 3600 * 1000).toISOString(),
    },
    {
      id: 'rep-004',
      url: 'https://careers-google-hiring-portal.buzz/apply',
      domain: 'careers-google-hiring-portal.buzz',
      category: 'fake_recruitment',
      description: 'Recruitment scam demanding interview registration fees via UPI QR code.',
      status: 'pending',
      upvotes: 15,
      downvotes: 1,
      reporterReputation: 50,
      createdAt: new Date(Date.now() - 18 * 3600 * 1000).toISOString(),
    }
  ];

  for (const r of initialReports) {
    threatReports.set(r.id, r);
  }

  // 3. Seed Alerts
  const initialAlerts: Alert[] = [
    {
      id: 'alert-01',
      scanId: 'scan-paypa1-01',
      type: 'malicious_site',
      title: 'Malicious Brand Impersonation Detected',
      detail: 'paypa1-secure-login.com detected attempting brand spoofing of PayPal.',
      url: 'https://paypa1-secure-login.com/auth/verify',
      severity: 'high',
      isRead: false,
      isDismissed: false,
      createdAt: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    },
    {
      id: 'alert-02',
      scanId: 'scan-badssl-expired',
      type: 'cert_issue',
      title: 'Expired Certificate Encountered',
      detail: 'expired.badssl.com has an expired TLS certificate chain.',
      url: 'https://expired.badssl.com',
      severity: 'medium',
      isRead: false,
      isDismissed: false,
      createdAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
    },
    {
      id: 'alert-03',
      type: 'watchlist',
      title: 'Watchlist Expiry Warning: api.trustify-demo.org',
      detail: 'Certificate expires in 11 days. Scheduled renewal recommended.',
      url: 'https://api.trustify-demo.org',
      severity: 'medium',
      isRead: true,
      isDismissed: false,
      createdAt: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
    }
  ];

  for (const a of initialAlerts) {
    alerts.set(a.id, a);
  }

  // 4. Seed API Keys
  const defaultApiKey: ApiKeyRecord = {
    id: 'key-default-01',
    name: 'Production Extension Key',
    prefix: 'tf_live_9a7b',
    key: 'tf_live_9a7b4c81f02e5d6a78b9c0d1e2f3a4b5',
    createdAt: new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString(),
    lastUsedAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
  };
  apiKeys.set(defaultApiKey.id, defaultApiKey);

  // 5. Seed Watchlist
  const initialWatchlist: WatchlistDomain[] = [
    {
      id: 'watch-01',
      domain: 'trustify-portal.io',
      addedAt: new Date(Date.now() - 14 * 24 * 3600 * 1000).toISOString(),
      lastCheckedAt: new Date().toISOString(),
      status: 'healthy',
      expiresInDays: 85,
      certIssuer: "Let's Encrypt Authority R3",
    },
    {
      id: 'watch-02',
      domain: 'api.trustify-demo.org',
      addedAt: new Date(Date.now() - 20 * 24 * 3600 * 1000).toISOString(),
      lastCheckedAt: new Date().toISOString(),
      status: 'warning',
      expiresInDays: 11,
      certIssuer: 'DigiCert Global Root G2',
    }
  ];

  for (const w of initialWatchlist) {
    watchlist.set(w.id, w);
  }

  global.__TRUSTIFY_DB = {
    scans,
    threatReports,
    alerts,
    apiKeys,
    watchlist,
    userVotes,
    userProfile: {
      name: 'Security Analyst',
      email: 'analyst@trustify.local',
      role: 'Threat Analyst',
      reputation: 92,
    },
  };

  return global.__TRUSTIFY_DB;
}

export const db = initDb();

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const stats = await getScanStats();

  return {
    kpis: {
      totalScans: { value: stats.totalScans, deltaPct: 0 },
      safe: { value: stats.safeCount, deltaPct: 0 },
      threats: { value: stats.maliciousCount, deltaPct: 0 },
      avgResponseMs: { value: stats.avgLatency, deltaPct: 0 },
    },
    overview: {
      safePct: stats.safePct,
      suspiciousPct: stats.suspiciousPct,
      maliciousPct: stats.maliciousPct,
      trend: stats.sevenDayTrend.map(t => ({ day: t.day, scoreAvg: t.scoreAvg, scans: t.scans })),
    },
    threatTypes: stats.threatTypes,
    recentAlerts: stats.recentAlerts as any,
  };
}

