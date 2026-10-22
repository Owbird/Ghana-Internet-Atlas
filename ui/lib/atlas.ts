import { database } from '@/lib/db'

export type Operator = { name: string; asn: string; id: string; color: string }
export type Atlas = { operators: Operator[]; records: number; networks: number; updatedAt: string | null }
export type Measurement = { estimated_users: string; country_percent: string; measured_on: string }

export async function loadAtlas(): Promise<Atlas> {
  const client = await database().connect()
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
    const { rows: runs } = await client.query('SELECT id FROM runs WHERE active=true LIMIT 1')
    if (!runs.length) {
      await client.query('COMMIT')
      return { operators: [], records: 0, networks: 0, updatedAt: null }
    }
    const { rows } = await client.query(`SELECT asn::text AS id,max(name) AS name FROM routes
      WHERE run_id=$1 AND family(prefix)=4 GROUP BY asn ORDER BY name NULLS LAST,asn`, [runs[0].id])
    const counts = await client.query("SELECT count FROM run_counts WHERE run_id=$1 AND status='ok'", [runs[0].id])
    await client.query('COMMIT')
    return { records: Number(counts.rows[0]?.count || 0), networks: rows.length, updatedAt: new Date().toISOString(),
      operators: rows.map((r, i) => ({ id: r.id, asn: `AS${r.id}`, name: r.name || `AS${r.id}`,
        color: ['bg-[#f7c948]', 'bg-[#e6504f]', 'bg-[#5c8dff]', 'bg-[#8b68d2]'][i % 4] })) }
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {})
    throw e
  } finally { client.release() }
}
