import { Pool } from 'pg'

const globalDb = globalThis as unknown as { atlasPool?: Pool }
export function database() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required')
  return globalDb.atlasPool ??= new Pool({ connectionString: process.env.DATABASE_URL, max: 5, connectionTimeoutMillis: 10000, statement_timeout: 30000 })
}
