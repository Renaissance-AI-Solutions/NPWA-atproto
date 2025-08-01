import { bailableWait } from './util'

// reads values from a generator into a list
// breaks when isDone signals `true` AND `waitFor` completes OR when a max length is reached
// NOTE: does not signal generator to close. it *will* continue to produce values
export const readFromGenerator = async <T>(
  gen: AsyncGenerator<T>,
  isDone: (last?: T) => Promise<boolean> | boolean,
  waitFor: Promise<unknown> = Promise.resolve(),
  maxLength = Number.MAX_SAFE_INTEGER,
): Promise<T[]> => {
  const evts: T[] = []
  let bail: undefined | (() => void)
  let hasBroke = false
  const awaitDone = async () => {
    if (await isDone(evts.at(-1))) {
      return true
    }
    const bailable = bailableWait(20)
    await bailable.wait()
    bail = bailable.bail
    if (hasBroke) return false
    return await awaitDone()
  }
  const breakOn: Promise<void> = new Promise((resolve) => {
    waitFor.then(() => {
      awaitDone().then(() => resolve())
    })
  })

  try {
    while (evts.length < maxLength) {
      const maybeEvt = await Promise.race([gen.next(), breakOn])
      if (!maybeEvt) break
      const evt = maybeEvt as IteratorResult<T>
      if (evt.done) break
      evts.push(evt.value)
    }
  } finally {
    hasBroke = true
    bail && bail()
  }
  return evts
}

export type Deferrable = {
  resolve: () => void
  complete: Promise<void>
}

export const createDeferrable = (): Deferrable => {
  let resolve
  const promise: Promise<void> = new Promise((res) => {
    resolve = () => res()
  })
  return { resolve, complete: promise }
}

export const createDeferrables = (count: number): Deferrable[] => {
  const list: Deferrable[] = []
  for (let i = 0; i < count; i++) {
    list.push(createDeferrable())
  }
  return list
}

export const allComplete = async (deferrables: Deferrable[]): Promise<void> => {
  await Promise.all(deferrables.map((d) => d.complete))
}

export class AsyncBuffer<T> {
  private buffer: T[] = []
  private promise: Promise<void>
  private resolve: () => void
  private closed = false
  private toThrow: unknown | undefined

  constructor(public maxSize?: number) {
    // Initializing to satisfy types/build, immediately reset by resetPromise()
    this.promise = Promise.resolve()
    this.resolve = () => null
    this.resetPromise()
  }

  get curr(): T[] {
    return this.buffer
  }

  get size(): number {
    return this.buffer.length
  }

  get isClosed(): boolean {
    return this.closed
  }

  resetPromise() {
    this.promise = new Promise<void>((r) => (this.resolve = r))
  }

  push(item: T) {
    this.buffer.push(item)
    this.resolve()
  }

  pushMany(items: T[]) {
    items.forEach((i) => this.buffer.push(i))
    this.resolve()
  }

  async *events(): AsyncGenerator<T> {
    while (true) {
      if (this.closed && this.buffer.length === 0) {
        if (this.toThrow) {
          throw this.toThrow
        } else {
          return
        }
      }
      await this.promise
      if (this.toThrow) {
        throw this.toThrow
      }
      if (this.maxSize && this.size > this.maxSize) {
        throw new AsyncBufferFullError(this.maxSize)
      }
      const [first, ...rest] = this.buffer
      if (first) {
        this.buffer = rest
        yield first
      } else {
        this.resetPromise()
      }
    }
  }

  throw(err: unknown) {
    this.toThrow = err
    this.closed = true
    this.resolve()
  }

  close() {
    this.closed = true
    this.resolve()
  }
}

export class AsyncBufferFullError extends Error {
  constructor(maxSize: number) {
    super(`ReachedMaxBufferSize: ${maxSize}`)
  }
}

/**
 * Utility function that behaves like {@link Promise.allSettled} but returns the
 * same result as {@link Promise.all} in case every promise is fulfilled, and
 * throws an {@link AggregateError} if there are more than one errors.
 */
export function allFulfilled<T extends readonly unknown[] | []>(
  promises: T,
): Promise<{ -readonly [P in keyof T]: Awaited<T[P]> }>
export function allFulfilled<T>(
  promises: Iterable<T | PromiseLike<T>>,
): Promise<Awaited<T>[]>
export function allFulfilled(
  promises: Iterable<Promise<unknown>>,
): Promise<unknown[]> {
  return Promise.allSettled(promises).then(handleAllSettledErrors)
}

export function handleAllSettledErrors<
  T extends readonly PromiseSettledResult<unknown>[] | [],
>(
  results: T,
): {
  -readonly [P in keyof T]: T[P] extends PromiseSettledResult<infer U>
    ? U
    : never
}
export function handleAllSettledErrors<T>(
  results: PromiseSettledResult<T>[],
): T[]
export function handleAllSettledErrors(
  results: PromiseSettledResult<unknown>[],
): unknown[] {
  const errors = results.filter(isRejectedResult).map(extractReason)
  if (errors.length === 0) {
    // No need to filter here, it is safe to assume that all promises are fulfilled
    return (results as PromiseFulfilledResult<unknown>[]).map(extractValue)
  }
  if (errors.length === 1) {
    throw errors[0]
  }
  throw new AggregateError(
    errors,
    `Multiple errors: ${errors.map(stringifyReason).join('\n')}`,
  )
}

export function isRejectedResult(
  result: PromiseSettledResult<unknown>,
): result is PromiseRejectedResult {
  return result.status === 'rejected'
}

function extractReason(result: PromiseRejectedResult): unknown {
  return result.reason
}

export function isFulfilledResult<T>(
  result: PromiseSettledResult<T>,
): result is PromiseFulfilledResult<T> {
  return result.status === 'fulfilled'
}

function extractValue<T>(result: PromiseFulfilledResult<T>): T {
  return result.value
}

function stringifyReason(reason: unknown): string {
  if (reason instanceof Error) {
    return reason.message
  }
  return String(reason)
}
