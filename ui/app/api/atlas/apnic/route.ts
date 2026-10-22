import { NextRequest, NextResponse } from 'next/server'
import { database } from '@/lib/db'

export const dynamic = 'force-dynamic'
export async function GET(request: NextRequest) {
  const asn = request.nextUrl.searchParams.get('asn') || ''
  if (!/^[1-9]\d{0,9}$/.test(asn) || Number(asn) > 4294967295) {
    return NextResponse.json({ error: 'Select a valid ASN before loading APNIC data.' }, { status: 400 })
  }
  const client = await Promise.resolve().then(() => database().connect()).catch(() => null)
  if (!client) return NextResponse.json({ error: 'Unable to connect to the database.' }, { status: 503 })
  try {
    const active = await client.query(`SELECT 1 FROM routes r JOIN runs ON runs.id=r.run_id
      WHERE runs.active=true AND r.asn=$1 AND family(r.prefix)=4 LIMIT 1`, [asn])
    if (!active.rowCount) return NextResponse.json({ error: 'ASN is not in the active collection run.' }, { status: 404 })
    const optional = await client.query("SELECT to_regclass('asn_measurements') AS name")
    const measurement = optional.rows[0].name ? (await client.query(`SELECT estimated_users::text,
      country_percent::text,measured_on::text FROM asn_measurements WHERE country='GH' AND asn=$1
      ORDER BY measured_on DESC,fetched_at DESC,window_days DESC LIMIT 1`, [asn])).rows[0] || null : null
    return NextResponse.json({ asn, measurement }, { headers: { 'Cache-Control': 'no-store' } })
  } catch {
    return NextResponse.json({ error: 'Unable to load APNIC data.' }, { status: 503 })
  } finally { client.release() }
}
