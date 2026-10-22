import { NextResponse } from 'next/server'
import { loadAtlas } from '@/lib/atlas'

export const dynamic = 'force-dynamic'
export async function GET() {
  try {
    return NextResponse.json(await loadAtlas(), { headers: { 'Cache-Control': 'no-store' } })
  } catch {
    return NextResponse.json({ error: 'Unable to load atlas data. Check the database configuration and schema.' }, { status: 503 })
  }
}
