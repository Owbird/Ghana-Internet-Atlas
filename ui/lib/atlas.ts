import { database } from '@/lib/db'
import { announcedAddresses, riskyPorts, riskyTags } from '@/lib/exposure'

export type Exposure = { scanned: number; records: number; exposed: number; ports: Record<string, number>; tags: Record<string, number> }
export type Operator = Exposure & { name: string; asn: string; id: string; color: string; prefixes: string[]; announced: number }
export type Atlas = { operators: Operator[]; records: number; networks: number; updatedAt: string | null; total: number; scanned: number; retry: number; exhausted: number; startedAt: string | null; firstLookup: string | null; lastLookup: string | null; ports: Record<string, number> }
export type Measurement = { estimated_users: string; country_percent: string; measured_on: string }
export const emptyExposure: Exposure = { scanned: 0, records: 0, exposed: 0, ports: {}, tags: {} }

export async function loadAtlas(): Promise<Atlas> {
  const client = await database().connect()
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
    const { rows: runs } = await client.query('SELECT id,total,created_at FROM runs WHERE active=true LIMIT 1')
    const empty: Atlas = { operators: [], records: 0, networks: 0, updatedAt: null, total: 0, scanned: 0, retry: 0, exhausted: 0, startedAt: null, firstLookup: null, lastLookup: null, ports: {} }
    if (!runs.length) { await client.query('COMMIT'); return empty }
    const run = runs[0]
    const { rows } = await client.query(`SELECT asn::text AS id,max(name) AS name,
      array_agg(prefix::text ORDER BY prefix) AS prefixes FROM routes
      WHERE run_id=$1 AND family(prefix)=4 GROUP BY asn ORDER BY name NULLS LAST,asn`, [run.id])
    const counts = await client.query('SELECT status,count FROM run_counts WHERE run_id=$1', [run.id])
    const statuses = Object.fromEntries(counts.rows.map(r => [r.status, Number(r.count)]))
    // Attribute overlapping announcements to the most specific prefix, then lowest ASN.
    // National metrics include all observations once, including any unattributed addresses.
    const stats = await client.query(`WITH attributed AS MATERIALIZED (
      SELECT DISTINCT ON (o.ip) o.ip,r.asn::text AS asn
      FROM routes r JOIN observations o ON o.run_id=r.run_id
        AND o.ip >= host(network(r.prefix))::inet AND o.ip <= host(broadcast(r.prefix))::inet
      WHERE r.run_id=$1 AND family(r.prefix)=4
      ORDER BY o.ip,masklen(r.prefix) DESC,r.asn
    ), base AS MATERIALIZED (
      SELECT a.asn,o.status,o.fetched_at,
        CASE WHEN o.status='ok' AND jsonb_typeof(o.payload->'ports')='array' THEN o.payload->'ports' ELSE '[]'::jsonb END AS ports,
        CASE WHEN o.status='ok' AND jsonb_typeof(o.payload->'tags')='array' THEN o.payload->'tags' ELSE '[]'::jsonb END AS tags
      FROM observations o LEFT JOIN attributed a ON a.ip=o.ip WHERE o.run_id=$1
    ), metrics AS (
      SELECT asn,GROUPING(asn) AS national,
        count(*) FILTER (WHERE status IN ('ok','no_data'))::int AS scanned,
        count(*) FILTER (WHERE status='ok')::int AS records,
        count(*) FILTER (WHERE status='ok' AND (ports @> ANY($2::jsonb[]) OR tags ?| $3::text[]))::int AS exposed,
        min(fetched_at) AS first_lookup,max(fetched_at) AS last_lookup
      FROM base GROUP BY GROUPING SETS ((asn),())
    ), port_counts AS (
      SELECT asn,GROUPING(asn) AS national,port,count(*)::int AS count FROM base
      CROSS JOIN LATERAL (SELECT DISTINCT value AS port FROM jsonb_array_elements_text(ports) WHERE value ~ '^[0-9]{1,5}$') p
      GROUP BY GROUPING SETS ((asn,port),(port))
    ), tag_counts AS (
      SELECT asn,GROUPING(asn) AS national,tag,count(*)::int AS count FROM base
      CROSS JOIN LATERAL (SELECT DISTINCT value AS tag FROM jsonb_array_elements_text(tags) WHERE value=ANY($3::text[])) t
      GROUP BY GROUPING SETS ((asn,tag),(tag))
    ) SELECT m.*,
      coalesce((SELECT jsonb_object_agg(port,count) FROM port_counts p WHERE p.national=m.national AND p.asn IS NOT DISTINCT FROM m.asn),'{}') AS ports,
      coalesce((SELECT jsonb_object_agg(tag,count) FROM tag_counts t WHERE t.national=m.national AND t.asn IS NOT DISTINCT FROM m.asn),'{}') AS tags
      FROM metrics m`, [run.id, riskyPorts.map(p => JSON.stringify([p.port])), riskyTags.map(t => t.tag)])
    await client.query('COMMIT')
    const national = stats.rows.find(r => r.national === 1)
    return { ...empty, total: Number(run.total), scanned: national?.scanned || 0, records: national?.records || 0,
      retry: statuses.retry || 0, exhausted: statuses.exhausted || 0, startedAt: run.created_at.toISOString(),
      firstLookup: national?.first_lookup?.toISOString() || null, lastLookup: national?.last_lookup?.toISOString() || null,
      ports: national?.ports || {}, networks: rows.length, updatedAt: new Date().toISOString(),
      operators: rows.map((r, i) => {
        const s = stats.rows.find(s => s.national === 0 && s.asn === r.id)
        return { ...emptyExposure, scanned: s?.scanned || 0, records: s?.records || 0, exposed: s?.exposed || 0,
          ports: s?.ports || {}, tags: s?.tags || {}, id: r.id, asn: `AS${r.id}`, name: r.name || `AS${r.id}`,
          prefixes: r.prefixes, announced: announcedAddresses(r.prefixes),
          color: ['bg-[#f7c948]', 'bg-[#e6504f]', 'bg-[#5c8dff]', 'bg-[#8b68d2]'][i % 4] }
      }) }
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e }
  finally { client.release() }
}
