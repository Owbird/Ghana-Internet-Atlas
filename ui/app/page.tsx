import AtlasDashboard from '@/components/atlas-dashboard'
import { loadAtlas } from '@/lib/atlas'

export const dynamic = 'force-dynamic'
export default async function Page() {
  try {
    const initialData = await loadAtlas()
    return <AtlasDashboard initialData={initialData} />
  } catch {
    return <AtlasDashboard initialData={null} initialError="Unable to load atlas data. Check the database configuration and schema." />
  }
}
