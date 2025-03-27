/**
 * A fast LRU (Least Recently Used) cache implementation for storing permission check results
 */
export class PermissionCache {
  private readonly cache: Map<string, { value: boolean; expiresAt: number }>;
  private readonly maxSize: number;
  private readonly ttl: number; // Time-to-live in milliseconds

  constructor(maxSize = 1000, ttl = 5 * 60 * 1000) {
    // Default 5-minute TTL
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
  }

  /**
   * Creates a cache key from permission check parameters
   */
  private createKey(role: string, resource: string, permission: string): string {
    return `${role}:${resource}:${permission}`;
  }

  /**
   * Retrieves a value from the cache
   * @returns The cached value or undefined if not found or expired
   */
  get(role: string, resource: string, permission: string): boolean | undefined {
    const key = this.createKey(role, resource, permission);
    const entry = this.cache.get(key);

    if (!entry) {
      return undefined;
    }

    // Check if entry has expired
    if (entry.expiresAt < Date.now()) {
      this.cache.delete(key);
      return undefined;
    }

    // Move the entry to the end of the map to maintain LRU order
    this.cache.delete(key);
    this.cache.set(key, entry);

    return entry.value;
  }

  /**
   * Stores a value in the cache
   */
  set(role: string, resource: string, permission: string, value: boolean): void {
    const key = this.createKey(role, resource, permission);

    // If cache is at capacity, remove the least recently used item (first item in the map)
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(key, {
      value,
      expiresAt: Date.now() + this.ttl,
    });
  }

  /**
   * Clears the entire cache
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Invalidates cached entries for a specific role
   */
  invalidateRole(role: string): void {
    for (const key of this.cache.keys()) {
      if (key.startsWith(`${role}:`)) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Invalidates cached entries for a specific resource
   */
  invalidateResource(resource: string): void {
    for (const key of this.cache.keys()) {
      const parts = key.split(":");
      if (parts[1] === resource) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Returns the number of entries in the cache
   */
  size(): number {
    return this.cache.size;
  }
}
