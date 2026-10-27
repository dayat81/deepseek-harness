import { readFileSync } from 'node:fs'

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'magnon'
export const inject = ['tools']

const collector = () => (process.env.MAGNON_COLLECTOR_URL || 'http://127.0.0.1:8081').replace(/\/$/, '')

function cookie(): string {
  const file = process.env.MAGNON_SESSION_FILE || '/var/lib/magnon/session'
  const token = readFileSync(file, 'utf8').trim()
  return `magnon_session=${token}`
}

async function call(method: string, path: string, body?: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(collector() + path, {
    method,
    headers: {
      cookie: cookie(),
      'content-type': 'application/json',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>
    if (!response.ok) return { error: String(parsed.error || text.slice(0, 300)) }
    return parsed
  } catch {
    return { error: text.slice(0, 300) || 'collector_unreachable' }
  }
}

export function apply(ctx: Context) {
  ctx.tools.register(defineTool({
    name: 'magnon_captures',
    description: 'List packet captures for this sponsor. Each row has the tester Gmail, the app name, and the size in bytes. Do not expect a provider, a place, or a time.',
    parameters: {
      refresh: { type: 'boolean', description: 'Ignored.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute() {
      const payload = await call('GET', '/api/magnon/pcap/captures')
      return JSON.stringify(payload.captures || payload)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'magnon_jev',
    description: 'Jev is the only classifier. Returns the stored label, probability, and earlier turns. The first call classifies the capture. Later calls return the same label. Pass the sponsor question as note and your own answer as reply.',
    parameters: {
      object: { type: 'string', required: true, description: 'pcap_object from magnon_captures' },
      note: { type: 'string', description: 'The sponsor question to store with this capture' },
      reply: { type: 'string', description: 'Your answer, after you have quoted the Jev label' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const payload = await call('POST', '/api/magnon/pcap/jev', {
        object: args.object,
        note: args.note || '',
        reply: args.reply || '',
      })
      if (payload.error) return String(payload.error)
      return `label: ${payload.label}\nprobability: ${payload.probability}\nturns: ${JSON.stringify(payload.turns || [])}`
    },
  }))

  ctx.tools.register(defineTool({
    name: 'magnon_tcpdump',
    description: 'Read the capture with tcpdump. Pass read flags and filter words. A bare tcp-rst means TCP RST packets. Do not pass -i or -w. Quote only the lines this tool returns.',
    parameters: {
      object: { type: 'string', required: true, description: 'pcap_object from magnon_captures' },
      args: { type: 'string', required: true, description: 'tcpdump read flags and filter words, without -r, -i, or -w' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const payload = await call('POST', '/api/magnon/pcap/tcpdump', {
        object: args.object,
        args: args.args,
      })
      if (payload.error) return String(payload.error)
      return String(payload.output || '')
    },
  }))
}
