import { NextResponse } from 'next/server';
import { getDashboardSummary } from '@/lib/store';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET() {
  const summary = await getDashboardSummary();
  return NextResponse.json(summary, {
    headers: {
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
    },
  });
}

