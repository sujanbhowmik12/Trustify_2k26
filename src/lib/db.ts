import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

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

declare global {
  // eslint-disable-next-line no-var
  var __TRUSTIFY_SQLITE_INSTANCE: DatabaseSync | undefined;
}

function resolveDbPath(): string {
  if (process.env.TRUSTIFY_DB_PATH) {
    return process.env.TRUSTIFY_DB_PATH;
  }
  const cwd = process.cwd();
  if (fs.existsSync(path.join(cwd, 'package.json'))) {
    return path.join(cwd, 'trustify.db');
  }
  const inSub = path.join(cwd, 'Trustify', 'trustify.db');
  if (fs.existsSync(path.join(cwd, 'Trustify'))) {
    return inSub;
  }
  return path.join(cwd, 'trustify.db');
}

export function getDatabase(): DatabaseSync {
  if (global.__TRUSTIFY_SQLITE_INSTANCE) {
    return global.__TRUSTIFY_SQLITE_INSTANCE;
  }

  const dbPath = resolveDbPath();
  const db = new DatabaseSync(dbPath);

  try {
    db.exec('PRAGMA journal_mode = WAL;');
  } catch {
    // fallback if WAL unavailable
  }

  // Scans table storing every scan result: url, score, verdict, latency, created_at
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      score INTEGER NOT NULL,
      verdict TEXT NOT NULL,
      latency REAL NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Alerts table
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      scan_id TEXT,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      detail TEXT NOT NULL,
      url TEXT,
      severity TEXT NOT NULL,
      is_read INTEGER DEFAULT 0,
      is_dismissed INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );
  `);

  global.__TRUSTIFY_SQLITE_INSTANCE = db;
  return db;
}

export function saveScanRecord(record: {
  id?: string;
  url: string;
  score: number;
  verdict: string;
  latency: number;
  created_at?: string;
}): ScanRecord {
  const db = getDatabase();
  const id = record.id || 'scan-' + crypto.randomUUID().slice(0, 8);
  const created_at = record.created_at || new Date().toISOString();
  const score = Math.round(Number(record.score) || 0);
  const latency = Math.round(Number(record.latency) || 0);
  const verdict = (record.verdict || 'unknown').toLowerCase();

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO scans (id, url, score, verdict, latency, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(id, record.url, score, verdict, latency, created_at);

  return {
    id,
    url: record.url,
    score,
    verdict: verdict as any,
    latency,
    created_at,
  };
}

export function saveAlertRecord(alert: {
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
}) {
  const db = getDatabase();
  const id = alert.id || 'alert-' + crypto.randomUUID().slice(0, 8);
  const scan_id = alert.scan_id || alert.scanId || null;
  const is_read = alert.is_read ? 1 : alert.isRead ? 1 : 0;
  const is_dismissed = alert.is_dismissed ? 1 : alert.isDismissed ? 1 : 0;
  const created_at = alert.created_at || alert.createdAt || new Date().toISOString();

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO alerts (id, scan_id, type, title, detail, url, severity, is_read, is_dismissed, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(id, scan_id, alert.type, alert.title, alert.detail, alert.url || null, alert.severity, is_read, is_dismissed, created_at);
}

export function getAllScanRecords(limit = 100): ScanRecord[] {
  const db = getDatabase();
  const stmt = db.prepare(`SELECT * FROM scans ORDER BY created_at DESC LIMIT ?`);
  return (stmt.all(limit) as any[]).map(row => ({
    id: row.id,
    url: row.url,
    score: Number(row.score),
    verdict: row.verdict,
    latency: Number(row.latency),
    created_at: row.created_at,
  }));
}

export function getScanStats(): StatsResponse {
  const db = getDatabase();

  const agg = db.prepare(`
    SELECT
      COUNT(*) as total_scans,
      SUM(CASE WHEN LOWER(verdict) = 'safe' THEN 1 ELSE 0 END) as safe_count,
      SUM(CASE WHEN LOWER(verdict) = 'malicious' THEN 1 ELSE 0 END) as malicious_count,
      SUM(CASE WHEN LOWER(verdict) = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
      AVG(latency) as avg_latency
    FROM scans
  `).get() as any;

  const totalScans = Number(agg?.total_scans || 0);
  const safeCount = Number(agg?.safe_count || 0);
  const maliciousCount = Number(agg?.malicious_count || 0);
  const suspiciousCount = Number(agg?.suspicious_count || 0);
  const avgLatency = agg?.avg_latency ? Math.round(Number(agg.avg_latency)) : 0;

  const safePct = totalScans > 0 ? Math.round((safeCount / totalScans) * 100) : 0;
  const suspiciousPct = totalScans > 0 ? Math.round((suspiciousCount / totalScans) * 100) : 0;
  const maliciousPct = totalScans > 0 ? Math.max(0, 100 - safePct - suspiciousPct) : 0;

  // 7-day trend
  const allRows = db.prepare(`SELECT score, created_at FROM scans`).all() as any[];
  const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const sevenDayTrend: TrendDay[] = [];

  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    const dayName = dayNames[d.getDay()];

    const matching = allRows.filter(r => typeof r.created_at === 'string' && r.created_at.startsWith(dateStr));
    const count = matching.length;
    const scoreAvg = count > 0 ? Math.round(matching.reduce((acc, r) => acc + Number(r.score || 0), 0) / count) : 0;

    sevenDayTrend.push({
      date: dateStr,
      day: dayName,
      scans: count,
      scoreAvg,
    });
  }

  // Recent alerts
  const alertRows = db.prepare(`
    SELECT * FROM alerts 
    WHERE is_dismissed = 0 
    ORDER BY created_at DESC 
    LIMIT 5
  `).all() as any[];

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

