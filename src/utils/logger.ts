/**
 * Default logger implementation
 */
export const defaultLogger = {
  debug: (message: string, ...args: unknown[]) => {
    if (process.env.NODE_ENV === "development") {
      console.debug(`[RABAC] ${message}`, ...args);
    }
  },
  info: (message: string, ...args: unknown[]) => {
    console.info(`[RABAC] ${message}`, ...args);
  },
  warn: (message: string, ...args: unknown[]) => {
    console.warn(`[RABAC] ${message}`, ...args);
  },
  error: (message: string, ...args: unknown[]) => {
    console.error(`[RABAC] ${message}`, ...args);
  },
};

/**
 * Silent logger that doesn't output anything
 */
export const silentLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
