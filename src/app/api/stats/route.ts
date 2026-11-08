import { NextResponse } from 'next/server';
import { getScanStats } from '@/lib/db';

export async function GET() {
  try {
    const stats = getScanStats();
    return NextResponse.json(stats);
  } catch (err: any) {
    return NextResponse.json(
      { error: { code: 'STATS_ERROR', message: err.message || 'Failed to retrieve scan statistics' } },
      { status: 500 }
    );
  }
}

