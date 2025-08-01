import * as http from 'node:http'
import { AddressInfo } from 'node:net'
import { MINUTE } from '@atproto/common'
import { LexiconDoc } from '@atproto/lexicon'
import { XrpcClient } from '@atproto/xrpc'
import * as xrpcServer from '../src'
import { RateLimiter } from '../src'
import { closeServer, createServer } from './_util'

const LEXICONS: LexiconDoc[] = [
  {
    lexicon: 1,
    id: 'io.example.routeLimit',
    defs: {
      main: {
        type: 'query',
        parameters: {
          type: 'params',
          required: ['str'],
          properties: {
            str: { type: 'string' },
          },
        },
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
  {
    lexicon: 1,
    id: 'io.example.routeLimitReset',
    defs: {
      main: {
        type: 'query',
        parameters: {
          type: 'params',
          required: ['count'],
          properties: {
            count: { type: 'integer' },
          },
        },
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
  {
    lexicon: 1,
    id: 'io.example.sharedLimitOne',
    defs: {
      main: {
        type: 'query',
        parameters: {
          type: 'params',
          required: ['points'],
          properties: {
            points: { type: 'integer' },
          },
        },
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
  {
    lexicon: 1,
    id: 'io.example.sharedLimitTwo',
    defs: {
      main: {
        type: 'query',
        parameters: {
          type: 'params',
          required: ['points'],
          properties: {
            points: { type: 'integer' },
          },
        },
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
  {
    lexicon: 1,
    id: 'io.example.toggleLimit',
    defs: {
      main: {
        type: 'query',
        parameters: {
          type: 'params',
          properties: {
            shouldCount: { type: 'boolean' },
          },
        },
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
  {
    lexicon: 1,
    id: 'io.example.noLimit',
    defs: {
      main: {
        type: 'query',
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
  {
    lexicon: 1,
    id: 'io.example.nonExistent',
    defs: {
      main: {
        type: 'query',
        output: {
          encoding: 'application/json',
        },
      },
    },
  },
]

describe('Parameters', () => {
  let s: http.Server
  const server = xrpcServer.createServer(LEXICONS, {
    rateLimits: {
      creator: (opts) => RateLimiter.memory(opts),
      bypass: ({ req }) => req.headers['x-ratelimit-bypass'] === 'bypass',
      shared: [
        {
          name: 'shared-limit',
          durationMs: 5 * MINUTE,
          points: 6,
        },
      ],
      global: [
        {
          name: 'global-ip',
          durationMs: 5 * MINUTE,
          points: 100,
        },
      ],
    },
  })
  server.method('io.example.routeLimit', {
    rateLimit: {
      durationMs: 5 * MINUTE,
      points: 5,
      calcKey: ({ params }) => params.str as string,
    },
    handler: (ctx: { params: xrpcServer.Params }) => ({
      encoding: 'json',
      body: ctx.params,
    }),
  })
  server.method('io.example.routeLimitReset', {
    rateLimit: {
      durationMs: 5 * MINUTE,
      points: 2,
    },
    handler: (ctx: xrpcServer.XRPCReqContext) => {
      if (ctx.params.count === 1) {
        ctx.resetRouteRateLimits()
      }

      return {
        encoding: 'json',
        body: {},
      }
    },
  })
  server.method('io.example.sharedLimitOne', {
    rateLimit: {
      name: 'shared-limit',
      calcPoints: ({ params }) => params.points as number,
    },
    handler: (ctx: { params: xrpcServer.Params }) => ({
      encoding: 'json',
      body: ctx.params,
    }),
  })
  server.method('io.example.sharedLimitTwo', {
    rateLimit: {
      name: 'shared-limit',
      calcPoints: ({ params }) => params.points as number,
    },
    handler: (ctx: { params: xrpcServer.Params }) => ({
      encoding: 'json',
      body: ctx.params,
    }),
  })
  server.method('io.example.toggleLimit', {
    rateLimit: [
      {
        durationMs: 5 * MINUTE,
        points: 5,
        calcPoints: ({ params }) => (params.shouldCount ? 1 : 0),
      },
      {
        durationMs: 5 * MINUTE,
        points: 10,
      },
    ],
    handler: (ctx: { params: xrpcServer.Params }) => ({
      encoding: 'json',
      body: ctx.params,
    }),
  })
  server.method('io.example.noLimit', {
    handler: () => ({
      encoding: 'json',
      body: {},
    }),
  })

  let client: XrpcClient
  beforeAll(async () => {
    s = await createServer(server)
    const { port } = s.address() as AddressInfo
    client = new XrpcClient(`http://localhost:${port}`, LEXICONS)
  })
  afterAll(async () => {
    await closeServer(s)
  })

  it('rate limits a given route', async () => {
    const makeCall = () => client.call('io.example.routeLimit', { str: 'test' })
    for (let i = 0; i < 5; i++) {
      await makeCall()
    }
    await expect(makeCall).rejects.toThrow('Rate Limit Exceeded')
  })

  it('can reset route rate limits', async () => {
    // Limit is 2.
    // Call 0 is OK (1/2).
    // Call 1 is OK (2/2), and resets the limit.
    // Call 2 is OK (1/2).
    // Call 3 is OK (2/2).
    for (let i = 0; i < 4; i++) {
      await client.call('io.example.routeLimitReset', { count: i })
    }

    // Call 4 exceeds the limit (3/2).
    await expect(
      client.call('io.example.routeLimitReset', { count: 4 }),
    ).rejects.toThrow('Rate Limit Exceeded')
  })

  it('rate limits on a shared route', async () => {
    await client.call('io.example.sharedLimitOne', { points: 1 })
    await client.call('io.example.sharedLimitTwo', { points: 1 })
    await client.call('io.example.sharedLimitOne', { points: 2 })
    await client.call('io.example.sharedLimitTwo', { points: 2 })
    await expect(
      client.call('io.example.sharedLimitOne', { points: 1 }),
    ).rejects.toThrow('Rate Limit Exceeded')
    await expect(
      client.call('io.example.sharedLimitTwo', { points: 1 }),
    ).rejects.toThrow('Rate Limit Exceeded')
  })

  it('applies multiple rate-limits', async () => {
    const makeCall = (shouldCount: boolean) =>
      client.call('io.example.toggleLimit', { shouldCount })
    for (let i = 0; i < 5; i++) {
      await makeCall(true)
    }
    await expect(() => makeCall(true)).rejects.toThrow('Rate Limit Exceeded')
    for (let i = 0; i < 4; i++) {
      await makeCall(false)
    }
    await expect(() => makeCall(false)).rejects.toThrow('Rate Limit Exceeded')
  })

  it('applies global limits', async () => {
    const makeCall = () => client.call('io.example.noLimit')
    const calls: Promise<unknown>[] = []
    for (let i = 0; i < 110; i++) {
      calls.push(makeCall())
    }
    await expect(Promise.all(calls)).rejects.toThrow('Rate Limit Exceeded')
  })

  it('applies global limits to xrpc catchall', async () => {
    const makeCall = () => client.call('io.example.nonExistent')
    await expect(makeCall()).rejects.toThrow('Rate Limit Exceeded')
  })

  it('can bypass rate limits', async () => {
    const makeCall = () =>
      client.call(
        'io.example.noLimit',
        {},
        {},
        { headers: { 'X-RateLimit-Bypass': 'bypass' } },
      )
    const calls: Promise<unknown>[] = []
    for (let i = 0; i < 110; i++) {
      calls.push(makeCall())
    }
    await Promise.all(calls)
  })
})
