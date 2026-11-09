import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { neon, NeonQueryFunction } from '@neondatabase/serverless';

export interface ScanRecord {
  id: string;
  url: string;
  score: number;
  verdict: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  latency: number;
  created_at: string;
}

export interface AlertRecord {
  id: string;
  scan_id?: string;
  type: string;
  title: string;
  detail: string;
  url?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  is_read: number;
  is_dismissed: number;
  created_at: string;
}

export interface TrendDay {
  date: string;
  day: string;
  scans: number;
  scoreAvg: number;
}

export interface StatsResponse {
  totalScans: number;
  total_scans: number;
  safeCount: number;
  safe_count: number;
  maliciousCount: number;
  malicious_count: number;
  suspiciousCount: number;
  suspicious_count: number;
  avgLatency: number;
  avg_latency: number;
  safePct: number;
  suspiciousPct: number;
  maliciousPct: number;
  sevenDayTrend: TrendDay[];
  trend: TrendDay[];
  recentAlerts: {
    id: string;
    scanId?: string;
    type: string;
    title: string;
    detail: string;
    url?: string;
    severity: string;
    isRead: boolean;
    isDismissed: boolean;
    createdAt: string;
  }[];
  recent_alerts: any[];
  threatTypes: { type: string; label: string; pct: number; count: number }[];
}

// Global in-memory storage for local development, test suites, and serverless fallback
declare global {
  // eslint-disable-next-line no-var
  var __TRUSTIFY_MEM_DB: {
    scans: Map<string, ScanRecord>;
    alerts: Map<string, AlertRecord>;
  } | undefined;
}

function getLocalDataFilePath(): string {
  return path.join(process.cwd(), '.trustify_data.json');
}

function loadLocalData(): { scans: ScanRecord[]; alerts: AlertRecord[] } | null {
  try {
    const filePath = getLocalDataFilePath();
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(raw);
    }
  } catch {
    // Ignore read errors
  }
  return null;
}

function saveLocalData(): void {
  try {
    const filePath = getLocalDataFilePath();
    const data = {
      scans: Array.from(memoryDb.scans.values()),
      alerts: Array.from(memoryDb.alerts.values()),
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch {
    // Ignore write errors (e.g. read-only filesystem on serverless)
  }
}

function getMemoryDb() {
  if (!global.__TRUSTIFY_MEM_DB) {
    const scansMap = new Map<string, ScanRecord>();
    const alertsMap = new Map<string, AlertRecord>();

    const localData = loadLocalData();
    if (localData) {
      if (Array.isArray(localData.scans)) {
        for (const s of localData.scans) {
          scansMap.set(s.id, s);
        }
      }
      if (Array.isArray(localData.alerts)) {
        for (const a of localData.alerts) {
          alertsMap.set(a.id, a);
        }
      }
    }

    global.__TRUSTIFY_MEM_DB = {
      scans: scansMap,
      alerts: alertsMap,
    };
  }
  return global.__TRUSTIFY_MEM_DB;
}

const memoryDb = getMemoryDb();

function syncWithGlobalStore() {
  if (typeof global !== 'undefined' && (global as any).__TRUSTIFY_DB) {
    const gdb = (global as any).__TRUSTIFY_DB;
    if (gdb.scans && typeof gdb.scans.entries === 'function') {
      for (const [id, scan] of gdb.scans.entries()) {
        if (!memoryDb.scans.has(id)) {
          memoryDb.scans.set(id, {
            id: scan.id,
            url: scan.inputUrl || scan.normalizedUrl || id,
            score: Math.round(Number(scan.score) || 0),
            verdict: (scan.verdict || 'unknown') as any,
            latency: Math.round(Number(scan.durationMs) || 0),
            created_at: scan.createdAt || new Date().toISOString(),
          });
        }
      }
    }
    if (gdb.alerts && typeof gdb.alerts.entries === 'function') {
      for (const [id, alert] of gdb.alerts.entries()) {
        if (!memoryDb.alerts.has(id)) {
          memoryDb.alerts.set(id, {
            id: alert.id,
            scan_id: alert.scanId,
            type: alert.type,
            title: alert.title,
            detail: alert.detail,
            url: alert.url,
            severity: alert.severity,
            is_read: alert.isRead ? 1 : 0,
            is_dismissed: alert.isDismissed ? 1 : 0,
            created_at: alert.createdAt,
          });
        }
      }
    }
  }
}

// Neon PostgreSQL connection handling
function getDatabaseUrl(): string | undefined {
  return (
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.POSTGRES_PRISMA_URL ||
    process.env.POSTGRES_URL_NON_POOLING
  );
}

let sqlClient: NeonQueryFunction<false, false> | null = null;
let tablesInitialized = false;

export function getPostgresClient(): NeonQueryFunction<false, false> | null {
  const dbUrl = getDatabaseUrl();
  if (!dbUrl) return null;
  if (!sqlClient) {
    sqlClient = neon(dbUrl);
  }
  return sqlClient;
}

export async function ensureTablesExist(): Promise<void> {
  if (tablesInitialized) return;
  const sql = getPostgresClient();
  if (!sql) return;

  try {
    await sql`
      CREATE TABLE IF NOT EXISTS scans (
        id VARCHAR(64) PRIMARY KEY,
        url TEXT NOT NULL,
        score INTEGER NOT NULL,
        verdict VARCHAR(32) NOT NULL,
        latency REAL NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `;
    await sql`
      CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS alerts (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64),
        type VARCHAR(64) NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL,
        url TEXT,
        severity VARCHAR(32) NOT NULL,
        is_read INTEGER DEFAULT 0,
        is_dismissed INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `;
    await sql`
      CREATE INDEX IF NOT EXISTS idx_alerts_dismissed_created ON alerts(is_dismissed, created_at);
    `;
    tablesInitialized = true;
  } catch (err) {
    console.warn('PostgreSQL table initialization warning (using memory fallback if needed):', err);
  }
}

let cachedScanStats: { data: StatsResponse; expiresAt: number } | null = null;

export function invalidateStatsCache(): void {
  cachedScanStats = null;
}

export async function saveScanRecord(record: {
  id?: string;
  url: string;
  score: number;
  verdict: string;
  latency: number;
  created_at?: string;
}): Promise<ScanRecord> {
  const id = record.id || 'scan-' + crypto.randomUUID().slice(0, 8);
  const created_at = record.created_at || new Date().toISOString();
  const score = Math.round(Number(record.score) || 0);
  const latency = Math.round(Number(record.latency) || 0);
  const verdict = (record.verdict || 'unknown').toLowerCase();

  const scanRecord: ScanRecord = {
    id,
    url: record.url,
    score,
    verdict: verdict as any,
    latency,
    created_at,
  };

  // Always update in-memory cache
  memoryDb.scans.set(id, scanRecord);
  cachedScanStats = null;
  saveLocalData();

  const sql = getPostgresClient();
  if (sql) {
    try {
      await ensureTablesExist();
      await sql`
        INSERT INTO scans (id, url, score, verdict, latency, created_at)
        VALUES (${id}, ${record.url}, ${score}, ${verdict}, ${latency}, ${created_at})
        ON CONFLICT (id) DO UPDATE SET
          url = EXCLUDED.url,
          score = EXCLUDED.score,
          verdict = EXCLUDED.verdict,
          latency = EXCLUDED.latency,
          created_at = EXCLUDED.created_at;
      `;
    } catch (err) {
      console.error('Failed to save scan record to PostgreSQL:', err);
    }
  }

  return scanRecord;
}

export async function saveAlertRecord(alert: {
  id?: string;
  scanId?: string;
  scan_id?: string;
  type: string;
  title: string;
  detail: string;
  url?: string;
  severity: string;
  isRead?: boolean;
  is_read?: number | boolean;
  isDismissed?: boolean;
  is_dismissed?: number | boolean;
  createdAt?: string;
  created_at?: string;
}): Promise<void> {
  const id = alert.id || 'alert-' + crypto.randomUUID().slice(0, 8);
  const scan_id = alert.scan_id || alert.scanId || undefined;
  const is_read = alert.is_read ? 1 : alert.isRead ? 1 : 0;
  const is_dismissed = alert.is_dismissed ? 1 : alert.isDismissed ? 1 : 0;
  const created_at = alert.created_at || alert.createdAt || new Date().toISOString();

  const alertRecord: AlertRecord = {
    id,
    scan_id,
    type: alert.type,
    title: alert.title,
    detail: alert.detail,
    url: alert.url,
    severity: (alert.severity as any) || 'low',
    is_read,
    is_dismissed,
    created_at,
  };

  // Always update in-memory cache
  memoryDb.alerts.set(id, alertRecord);
  cachedScanStats = null;
  saveLocalData();

  const sql = getPostgresClient();
  if (sql) {
    try {
      await ensureTablesExist();
      await sql`
        INSERT INTO alerts (id, scan_id, type, title, detail, url, severity, is_read, is_dismissed, created_at)
        VALUES (${id}, ${scan_id || null}, ${alert.type}, ${alert.title}, ${alert.detail}, ${alert.url || null}, ${alert.severity}, ${is_read}, ${is_dismissed}, ${created_at})
        ON CONFLICT (id) DO UPDATE SET
          scan_id = EXCLUDED.scan_id,
          type = EXCLUDED.type,
          title = EXCLUDED.title,
          detail = EXCLUDED.detail,
          url = EXCLUDED.url,
          severity = EXCLUDED.severity,
          is_read = EXCLUDED.is_read,
          is_dismissed = EXCLUDED.is_dismissed,
          created_at = EXCLUDED.created_at;
      `;
    } catch (err) {
      console.error('Failed to save alert record to PostgreSQL:', err);
    }
  }
}

export async function getAllScanRecords(limit = 100): Promise<ScanRecord[]> {
  const sql = getPostgresClient();
  if (sql) {
    try {
      await ensureTablesExist();
      const rows = await sql`
        SELECT id, url, score, verdict, latency, created_at
        FROM scans
        ORDER BY created_at DESC
        LIMIT ${limit}
      `;
      return rows.map((r: any) => ({
        id: String(r.id),
        url: String(r.url),
        score: Number(r.score),
        verdict: r.verdict,
        latency: Number(r.latency),
        created_at: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
      }));
    } catch (err) {
      console.error('Failed to get scan records from PostgreSQL:', err);
    }
  }

  // Fallback
  return Array.from(memoryDb.scans.values())
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, limit);
}

function getMemoryStats(): StatsResponse {
  syncWithGlobalStore();
  const scans = Array.from(memoryDb.scans.values());
  const totalScans = scans.length;
  let safeCount = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  let totalLatency = 0;

  for (const s of scans) {
    const v = (s.verdict || '').toLowerCase();
    if (v === 'safe') safeCount++;
    else if (v === 'malicious') maliciousCount++;
    else if (v === 'suspicious') suspiciousCount++;
    totalLatency += Number(s.latency || 0);
  }

  const avgLatency = totalScans > 0 ? Math.round(totalLatency / totalScans) : 0;
  const safePct = totalScans > 0 ? Math.round((safeCount / totalScans) * 100) : 0;
  const suspiciousPct = totalScans > 0 ? Math.round((suspiciousCount / totalScans) * 100) : 0;
  const maliciousPct = totalScans > 0 ? Math.max(0, 100 - safePct - suspiciousPct) : 0;

  const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const sevenDayTrend: TrendDay[] = [];

  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    const dayName = dayNames[d.getDay()];

    const matching = scans.filter(s => typeof s.created_at === 'string' && s.created_at.startsWith(dateStr));
    const count = matching.length;
    const scoreAvg = count > 0 ? Math.round(matching.reduce((acc, r) => acc + Number(r.score || 0), 0) / count) : 0;

    sevenDayTrend.push({
      date: dateStr,
      day: dayName,
      scans: count,
      scoreAvg,
    });
  }

  const alertRows = Array.from(memoryDb.alerts.values())
    .filter(a => !a.is_dismissed)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  const recentAlerts = alertRows.map(r => ({
    id: r.id,
    scanId: r.scan_id,
    type: r.type,
    title: r.title,
    detail: r.detail,
    url: r.url,
    severity: r.severity,
    isRead: Boolean(r.is_read),
    isDismissed: Boolean(r.is_dismissed),
    createdAt: r.created_at,
  }));

  const totalThreats = maliciousCount + suspiciousCount;
  const threatTypes = [
    {
      type: 'phishing',
      label: 'Phishing & Impersonation',
      pct: totalThreats > 0 ? Math.round((maliciousCount / totalThreats) * 60) : 0,
      count: maliciousCount,
    },
    {
      type: 'malware',
      label: 'Malware & Exploit Kits',
      pct: totalThreats > 0 ? Math.round((maliciousCount / totalThreats) * 40) : 0,
      count: 0,
    },
    {
      type: 'fake_payment',
      label: 'Payment / Banking Scams',
      pct: 0,
      count: 0,
    },
    {
      type: 'others',
      label: 'Certificate / Misconfig Anomalies',
      pct: totalThreats > 0 ? Math.round((suspiciousCount / totalThreats) * 100) : 0,
      count: suspiciousCount,
    },
  ];

  return {
    totalScans,
    total_scans: totalScans,
    safeCount,
    safe_count: safeCount,
    maliciousCount,
    malicious_count: maliciousCount,
    suspiciousCount,
    suspicious_count: suspiciousCount,
    avgLatency,
    avg_latency: avgLatency,
    safePct,
    suspiciousPct,
    maliciousPct,
    sevenDayTrend,
    trend: sevenDayTrend,
    recentAlerts,
    recent_alerts: recentAlerts,
    threatTypes,
  };
}

export function getScanStatsSync(): StatsResponse {
  if (cachedScanStats && cachedScanStats.expiresAt > Date.now()) {
    return cachedScanStats.data;
  }
  return getMemoryStats();
}

export async function getScanStats(): Promise<StatsResponse> {
  const now = Date.now();
  if (cachedScanStats && cachedScanStats.expiresAt > now) {
    return cachedScanStats.data;
  }

  const sql = getPostgresClient();
  if (sql) {
    try {
      await ensureTablesExist();

      const aggRows = await sql`
        SELECT
          COUNT(*)::int as total_scans,
          COALESCE(SUM(CASE WHEN LOWER(verdict) = 'safe' THEN 1 ELSE 0 END), 0)::int as safe_count,
          COALESCE(SUM(CASE WHEN LOWER(verdict) = 'malicious' THEN 1 ELSE 0 END), 0)::int as malicious_count,
          COALESCE(SUM(CASE WHEN LOWER(verdict) = 'suspicious' THEN 1 ELSE 0 END), 0)::int as suspicious_count,
          COALESCE(ROUND(AVG(latency)), 0)::int as avg_latency
        FROM scans;
      `;
      const agg = aggRows[0] || {};

      const totalScans = Number(agg.total_scans || 0);
      const safeCount = Number(agg.safe_count || 0);
      const maliciousCount = Number(agg.malicious_count || 0);
      const suspiciousCount = Number(agg.suspicious_count || 0);
      const avgLatency = Number(agg.avg_latency || 0);

      const safePct = totalScans > 0 ? Math.round((safeCount / totalScans) * 100) : 0;
      const suspiciousPct = totalScans > 0 ? Math.round((suspiciousCount / totalScans) * 100) : 0;
      const maliciousPct = totalScans > 0 ? Math.max(0, 100 - safePct - suspiciousPct) : 0;

      // 7-day trend
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - 7);
      const cutoffStr = cutoffDate.toISOString();

      const trendRows = await sql`
        SELECT score, created_at
        FROM scans
        WHERE created_at >= ${cutoffStr}
      `;

      const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const sevenDayTrend: TrendDay[] = [];

      for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const dateStr = d.toISOString().slice(0, 10);
        const dayName = dayNames[d.getDay()];

        const matching = trendRows.filter((r: any) => {
          const cat = r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at || '');
          return cat.startsWith(dateStr);
        });
        const count = matching.length;
        const scoreAvg = count > 0 ? Math.round(matching.reduce((acc: number, r: any) => acc + Number(r.score || 0), 0) / count) : 0;

        sevenDayTrend.push({
          date: dateStr,
          day: dayName,
          scans: count,
          scoreAvg,
        });
      }

      // Recent alerts
      const alertRows = await sql`
        SELECT id, scan_id, type, title, detail, url, severity, is_read, is_dismissed, created_at
        FROM alerts
        WHERE is_dismissed = 0
        ORDER BY created_at DESC
        LIMIT 5;
      `;

      const recentAlerts = alertRows.map((r: any) => ({
        id: String(r.id),
        scanId: r.scan_id || undefined,
        type: String(r.type),
        title: String(r.title),
        detail: String(r.detail),
        url: r.url || undefined,
        severity: String(r.severity),
        isRead: Boolean(r.is_read),
        isDismissed: Boolean(r.is_dismissed),
        createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
      }));

      const totalThreats = maliciousCount + suspiciousCount;
      const threatTypes = [
        {
          type: 'phishing',
          label: 'Phishing & Impersonation',
          pct: totalThreats > 0 ? Math.round((maliciousCount / totalThreats) * 60) : 0,
          count: maliciousCount,
        },
        {
          type: 'malware',
          label: 'Malware & Exploit Kits',
          pct: totalThreats > 0 ? Math.round((maliciousCount / totalThreats) * 40) : 0,
          count: 0,
        },
        {
          type: 'fake_payment',
          label: 'Payment / Banking Scams',
          pct: 0,
          count: 0,
        },
        {
          type: 'others',
          label: 'Certificate / Misconfig Anomalies',
          pct: totalThreats > 0 ? Math.round((suspiciousCount / totalThreats) * 100) : 0,
          count: suspiciousCount,
        },
      ];

      const response: StatsResponse = {
        totalScans,
        total_scans: totalScans,
        safeCount,
        safe_count: safeCount,
        maliciousCount,
        malicious_count: maliciousCount,
        suspiciousCount,
        suspicious_count: suspiciousCount,
        avgLatency,
        avg_latency: avgLatency,
        safePct,
        suspiciousPct,
        maliciousPct,
        sevenDayTrend,
        trend: sevenDayTrend,
        recentAlerts,
        recent_alerts: recentAlerts,
        threatTypes,
      };

      cachedScanStats = {
        data: response,
        expiresAt: now + 1500,
      };

      return response;
    } catch (err) {
      console.error('Failed to get scan stats from PostgreSQL, using memory store:', err);
    }
  }

  // Fallback to in-memory stats
  const memoryStats = getMemoryStats();
  cachedScanStats = {
    data: memoryStats,
    expiresAt: now + 1500,
  };
  return memoryStats;
}
