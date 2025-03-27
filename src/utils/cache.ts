/**
 * A fast LRU (Least Recently Used) cache implementation for storing permission check results
 */
export class PermissionCache {
  private readonly cache: Map<string, { value: boolean; expiresAt: number; version: number }>;
  private readonly maxSize: number;
  private readonly ttl: number; // Time-to-live in milliseconds
  private version: number;
  private readonly secureSalt: string;

  constructor(maxSize = 1000, ttl = 5 * 60 * 1000) {
    // Default 5-minute TTL
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
    this.version = 1;
    // Generate a random salt for cache keys
    this.secureSalt = Math.random().toString(36).substring(2, 15);
  }

  /**
   * Creates a secure cache key from permission check parameters
   * @private
   */
  private createKey(role: string, resource: string, permission: string): string {
    // Validate inputs to prevent key injection
    if (!role || !resource || !permission) {
      throw new Error("Invalid cache key parameters");
    }

    // Ensure roles, resources, and permissions are properly sanitized
    const sanitizedRole = this.sanitizeInput(role);
    const sanitizedResource = this.sanitizeInput(resource);
    const sanitizedPermission = this.sanitizeInput(permission);

    // Create a key with the secure salt to prevent key collision attacks
    return `${this.secureSalt}:${sanitizedRole}:${sanitizedResource}:${sanitizedPermission}`;
  }

  /**
   * Sanitizes input to prevent cache key injection attacks
   * @private
   */
  private sanitizeInput(input: string): string {
    if (typeof input !== "string") {
      return String(input);
    }
    // Remove any colons or other characters that could affect key structure
    return input.replace(/[:\n\r]/g, "_");
  }

  /**
   * Retrieves a value from the cache
   * @returns The cached value or undefined if not found or expired
   */
  get(role: string, resource: string, permission: string): boolean | undefined {
    try {
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

      // Check if entry is from an old version
      if (entry.version < this.version) {
        this.cache.delete(key);
        return undefined;
      }

      // Move the entry to the end of the map to maintain LRU order
      this.cache.delete(key);
      this.cache.set(key, entry);

      return entry.value;
    } catch (error) {
      // On any error, return undefined to force recalculation
      console.error("Cache retrieval error:", error);
      return undefined;
    }
  }

  /**
   * Stores a value in the cache
   */
  set(role: string, resource: string, permission: string, value: boolean): void {
    try {
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
        version: this.version,
      });
    } catch (error) {
      // On any error, log but don't throw
      console.error("Cache set error:", error);
    }
  }

  /**
   * Clears the entire cache
   */
  clear(): void {
    this.cache.clear();
    // Increment the version to invalidate any entries that might be accessed through race conditions
    this.version += 1;
  }

  /**
   * Invalidates cached entries for a specific role
   */
  invalidateRole(role: string): void {
    if (!role) return;

    try {
      const sanitizedRole = this.sanitizeInput(role);
      const rolePrefix = `${this.secureSalt}:${sanitizedRole}:`;

      for (const key of this.cache.keys()) {
        if (key.startsWith(rolePrefix)) {
          this.cache.delete(key);
        }
      }
    } catch (error) {
      // On any error, clear entire cache to be safe
      console.error("Error invalidating role cache:", error);
      this.clear();
    }
  }

  /**
   * Invalidates cached entries for a specific resource
   */
  invalidateResource(resource: string): void {
    if (!resource) return;

    try {
      const sanitizedResource = this.sanitizeInput(resource);

      for (const key of this.cache.keys()) {
        const parts = key.split(":");
        // Parts[2] is the resource part after salt and role
        if (parts.length > 2 && parts[2] === sanitizedResource) {
          this.cache.delete(key);
        }
      }
    } catch (error) {
      // On any error, clear entire cache to be safe
      console.error("Error invalidating resource cache:", error);
      this.clear();
    }
  }

  /**
   * Returns the number of entries in the cache
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Force cache version increment to invalidate all existing entries on next access
   */
  incrementVersion(): void {
    this.version += 1;
  }
}
