/**
 * Type definitions for Express-like middleware
 */

export interface Request {
  [key: string]: unknown;
  user?: {
    [key: string]: unknown;
    roles?: string[];
  };
}

export interface Response {
  [key: string]: unknown;
  status: (code: number) => Response;
  json: (data: unknown) => void;
}

export type NextFunction = (error?: unknown) => void;

export type Middleware = (req: Request, res: Response, next: NextFunction) => void | Promise<void>;
