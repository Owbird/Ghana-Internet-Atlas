export const riskyPorts = [
  { port: 179, name: 'BGP' }, { port: 23, name: 'Telnet' },
  { port: 21, name: 'FTP' }, { port: 3306, name: 'MySQL' },
  { port: 161, name: 'SNMP' }, { port: 8291, name: 'Winbox' },
]
export const riskyTags = [
  { tag: 'eol-product', name: 'End-of-life product' },
  { tag: 'eol-os', name: 'End-of-life OS' },
  { tag: 'database', name: 'Database' }, { tag: 'vpn', name: 'VPN' },
  { tag: 'self-signed', name: 'Self-signed' },
]
export const rate = (value: number, total: number) => total ? value / total * 100 : null
export function announcedAddresses(prefixes: string[]) {
  const ranges = prefixes.map(p => {
    const [ip, mask] = p.split('/')
    const start = ip.split('.').reduce((n, v) => n * 256 + Number(v), 0)
    return [start, start + 2 ** (32 - Number(mask))]
  }).sort((a, b) => a[0] - b[0])
  let total = 0, end = -1
  for (const [a, b] of ranges) { total += Math.max(0, b - Math.max(a, end)); end = Math.max(end, b) }
  return total
}
