import { NextResponse } from 'next/server';
import { getScanStats } from '@/lib/db';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET() {
  try {
    const stats = await getScanStats();
    return NextResponse.json(stats, {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
      },
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: { code: 'STATS_ERROR', message: err.message || 'Failed to retrieve scan statistics' } },
      { status: 500 }
    );
  }
}

