import type { BlockDecision } from './types.js';

interface CacheEntry {
  decision: BlockDecision;
  createdAt: number;
  staleAt: number;    // serve stale but refresh in background
  expireAt: number;   // don't serve at all after this
}

export class BlockCache {
  private cache = new Map<string, CacheEntry>();
  private maxEntries: number;
  private freshTtlMs: number;
  private staleTtlMs: number;

  constructor(maxEntries = 10000, freshTtlMs = 600_000, staleTtlMs = 86_400_000) {
    this.maxEntries = maxEntries;
    this.freshTtlMs = freshTtlMs;
    this.staleTtlMs = staleTtlMs;
  }

  /** Get a cached decision. Returns { decision, isStale } or null */
  get(purl: string): { decision: BlockDecision; isStale: boolean } | null {
    const entry = this.cache.get(purl);
    if (!entry) return null;

    const now = Date.now();
    if (now > entry.expireAt) {
      this.cache.delete(purl);
      return null;
    }

    return {
      decision: { ...entry.decision, cached: true },
      isStale: now > entry.staleAt,
    };
  }

  /** Store a decision in cache */
  set(purl: string, decision: BlockDecision): void {
    // Evict oldest if at capacity
    if (this.cache.size >= this.maxEntries) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) this.cache.delete(firstKey);
    }

    const now = Date.now();
    // Add jitter (±10%) to prevent thundering herd
    const jitter = 1 + (Math.random() * 0.2 - 0.1);

    this.cache.set(purl, {
      decision,
      createdAt: now,
      staleAt: now + this.freshTtlMs * jitter,
      expireAt: now + this.staleTtlMs * jitter,
    });
  }

  /** Flush the entire cache */
  flush(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}
