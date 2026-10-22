import { NextRequest, NextResponse } from 'next/server'
import { database } from '@/lib/db'

export const dynamic = 'force-dynamic'
export async function GET(request: NextRequest) {
  const asn = request.nextUrl.searchParams.get('asn') || ''
  if (!/^[1-9]\d{0,9}$/.test(asn) || Number(asn) > 4294967295) {
    return NextResponse.json({ error: 'Select a valid ASN before loading hosts.' }, { status: 400 })
  }
  const client = await Promise.resolve().then(() => database().connect()).catch(() => null)
  if (!client) return NextResponse.json({ error: 'Unable to connect to the database.' }, { status: 503 })
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
    const { rows } = await client.query(`SELECT r.id FROM runs r WHERE r.active=true
      AND EXISTS (SELECT 1 FROM routes WHERE run_id=r.id AND asn=$1 AND family(prefix)=4) LIMIT 1`, [asn])
    if (!rows.length) {
      await client.query('COMMIT')
      return NextResponse.json({ error: 'ASN is not in the active collection run.' }, { status: 404 })
    }
    const run = rows[0]
    const selected = asn
    const search = (request.nextUrl.searchParams.get('search') || '').slice(0, 200)
    const rawPage = Number(request.nextUrl.searchParams.get('page') || 1)
    const requestedPage = Number.isSafeInteger(rawPage) && rawPage > 0 ? Math.min(rawPage, 1000000) : 1
    const pageSize = 5
    const condition = `o.run_id=$1 AND o.status='ok' AND
      (SELECT r.asn::text FROM routes r WHERE r.run_id=o.run_id AND o.ip <<= r.prefix
        ORDER BY masklen(r.prefix) DESC,r.asn LIMIT 1)=$2
      AND ($3='' OR strpos(lower(host(o.ip)),lower($3))>0
        OR strpos(lower(coalesce(o.payload->'hostnames','[]'::jsonb)::text),lower($3))>0
        OR strpos(lower(coalesce(o.payload->'tags','[]'::jsonb)::text),lower($3))>0)`
    const params = [run.id, selected || '', search]
    const totalHosts = await client.query(`SELECT count(*)::text AS count FROM observations o WHERE ${condition}`, params)
    const total = Number(totalHosts.rows[0].count)
    const totalPages = Math.ceil(total / pageSize)
    const page = Math.min(requestedPage, Math.max(1, totalPages))
    const hosts = await client.query(`SELECT host(o.ip) AS ip,
      o.payload->'hostnames' AS hostnames,o.payload->'ports' AS ports,o.payload->'tags' AS tags,
      o.payload->'cpes' AS cpes,o.fetched_at,
      (SELECT r.prefix::text FROM routes r WHERE r.run_id=o.run_id AND r.asn::text=$2 AND o.ip <<= r.prefix ORDER BY masklen(r.prefix) DESC LIMIT 1) AS prefix
      FROM observations o WHERE ${condition} ORDER BY o.ip LIMIT $4 OFFSET $5`, [...params, pageSize, (page - 1) * pageSize])
    await client.query('COMMIT')
    return NextResponse.json({ asn, page, pageSize, totalHosts: total, totalPages,
      hasPrevious: page > 1, hasNext: page < totalPages,
      hosts: hosts.rows.map(h => ({ ip: h.ip, hostname: Array.isArray(h.hostnames) ? h.hostnames.filter((v: unknown) => typeof v === 'string').join(', ') || '—' : '—', ports: Array.isArray(h.ports) ? h.ports.filter((v: unknown) => Number.isInteger(v)) : [], tags: Array.isArray(h.tags) ? h.tags.filter((v: unknown) => typeof v === 'string') : [], software: Array.isArray(h.cpes) ? h.cpes.filter((v: unknown) => typeof v === 'string').join(', ') || 'Not reported' : 'Not reported', prefix: h.prefix, fetchedAt: h.fetched_at }))
    }, { headers: { 'Cache-Control': 'no-store' } })
  } catch {
    await client.query('ROLLBACK').catch(() => {})
    return NextResponse.json({ error: 'Unable to load hosts.' }, { status: 503 })
  } finally { client.release() }
}
