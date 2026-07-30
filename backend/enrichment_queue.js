/**
 * SentinelSEBI — Enrichment Job Queue (Phase 3)
 *
 * Enrichment must never sit in the scan request path. An RDAP timeout inside
 * `/phishing/analyze` would turn a working detection into a failed request, so
 * the verdict returns immediately and enrichment attaches afterwards.
 *
 * Implementation is an in-process serial queue rather than Redis/BullMQ,
 * matching the project's zero-extra-infrastructure deployment story. Serial
 * (concurrency 1) is deliberate: the upstream rate limits are the binding
 * constraint, so parallel workers would only burn tokens faster.
 *
 * Jobs are not persisted across restarts. That is acceptable because every
 * result is cached in `enrichment_cache` and re-enqueued on the next sighting
 * of the same indicator — a dropped job costs freshness, not correctness.
 */

const EnrichmentEngine = require('./engines/enrichment_engine');
const NetGuard = require('./net_guard');

const MAX_QUEUE_LENGTH = Number(process.env.SENTINEL_ENRICHMENT_QUEUE_MAX || 500);
const CACHE_TTL_HOURS = Number(process.env.SENTINEL_ENRICHMENT_TTL_HOURS || 24);

class EnrichmentQueue {
  constructor(db) {
    this.db = db;
    this.queue = [];
    this.inFlight = new Set(); // dedupes an indicator already queued
    this.running = false;
    this.stats = { enqueued: 0, completed: 0, failed: 0, cacheHits: 0, dropped: 0 };
  }

  /**
   * Queue a domain for enrichment.
   * Returns false when skipped (disabled, duplicate, or queue full) so the
   * caller can report honestly rather than implying work was scheduled.
   */
  enqueueDomain(domain, { onComplete } = {}) {
    if (!NetGuard.ENRICHMENT_ENABLED) return false;
    if (!domain || typeof domain !== 'string') return false;

    const key = `domain:${domain}`;
    if (this.inFlight.has(key)) return false;

    if (this.queue.length >= MAX_QUEUE_LENGTH) {
      this.stats.dropped++;
      console.warn(`[enrichment] queue full (${MAX_QUEUE_LENGTH}); dropping ${domain}`);
      return false;
    }

    this.inFlight.add(key);
    this.queue.push({ kind: 'domain', value: domain, key, onComplete });
    this.stats.enqueued++;
    this._drain();
    return true;
  }

  /** Process jobs one at a time; safe to call repeatedly. */
  async _drain() {
    if (this.running) return;
    this.running = true;

    while (this.queue.length > 0) {
      const job = this.queue.shift();
      try {
        await this._process(job);
        this.stats.completed++;
      } catch (err) {
        this.stats.failed++;
        console.error(`[enrichment] job failed for ${job.value}: ${err.message}`);
      } finally {
        this.inFlight.delete(job.key);
      }
    }

    this.running = false;
  }

  async _process(job) {
    if (job.kind !== 'domain') return;

    // Serve from cache when fresh — this is what keeps the upstream rate limits
    // survivable under bulk scanning.
    const cached = await new Promise((resolve) =>
      this.db.getEnrichment('domain', job.value, 'combined', (err, row) => resolve(row))
    );

    if (cached) {
      this.stats.cacheHits++;
      if (job.onComplete) job.onComplete(cached.payload, { fromCache: true });
      return;
    }

    const enrichment = await EnrichmentEngine.enrichDomain(job.value);

    await this.db.putEnrichment({
      indicatorType: 'domain',
      indicatorValue: job.value,
      source: 'combined',
      payload: enrichment,
      ttlHours: CACHE_TTL_HOURS,
    });

    if (job.onComplete) job.onComplete(enrichment, { fromCache: false });
  }

  getStats() {
    return {
      ...this.stats,
      queueLength: this.queue.length,
      running: this.running,
      enabled: NetGuard.ENRICHMENT_ENABLED,
    };
  }

  /** Test helper: resolve once the queue has fully drained. */
  async drained() {
    while (this.running || this.queue.length > 0) {
      await new Promise((r) => setTimeout(r, 25));
    }
  }
}

module.exports = EnrichmentQueue;
