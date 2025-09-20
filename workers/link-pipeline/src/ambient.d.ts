/* Ambient type declarations for Cloudflare Workflows and Workers bindings.
 *
 * Purpose:
 * - Satisfy TypeScript tooling for `cloudflare:workers` imports used by the
 *   link-pipeline workflow (WorkflowEntrypoint, WorkflowStep, WorkflowEvent, WorkerEntrypoint).
 * - Provide minimal typings for Cloudflare bindings used in the project:
 *   D1Database, R2Bucket, Ai, Workflow, WorkflowInstance.
 *
 * These are simplified type declarations to enable local type-checking and editor
 * IntelliSense. They are not complete and do not guarantee runtime behavior.
 */

declare module "cloudflare:workers" {
  // ---- Workflows core types ----

  export type RpcSerializable = any;

  export type WorkflowEvent<T = any> = {
    // Workflows docs often refer to `payload`, while some examples use `params`.
    // Include both for compatibility with differing examples/usages.
    payload?: Readonly<T>;
    params?: Readonly<T>;
    timestamp?: Date;
    instanceId?: string;
  };

  export type WorkflowRetryStrategy = {
    limit?: number;
    delay?: string; // e.g. "5 second"
    backoff?: "exponential" | "fixed" | "linear";
  };

  export type WorkflowStepConfig = {
    retries?: WorkflowRetryStrategy;
  };

  export interface WorkflowStep {
    // Basic step run with optional config
    do<T = RpcSerializable>(name: string, callback: () => Promise<T> | T): Promise<T>;
    do<T = RpcSerializable>(
      name: string,
      config: WorkflowStepConfig,
      callback: () => Promise<T> | T
    ): Promise<T>;

    // Sleep helper (duration strings like "1 second", "5 minute", etc.)
    sleep(name: string, duration: string): Promise<void>;
  }

  export type WorkflowInstance<T = any> = {
    id: string;
    status(): Promise<T | any>;
    cancel?(): Promise<void>;
  };

  export interface Workflow<T = any> {
    create(options: { params: T }): Promise<WorkflowInstance<T>>;
    createBatch?(options: { params: T[] }): Promise<WorkflowInstance<T>[]>;
  }

  // Base class for defining a Workflow
  export class WorkflowEntrypoint<Env = any, Params = any> {
    protected env: Env;

    // Subclasses override `run`
    run(event: WorkflowEvent<Params>, step: WorkflowStep): Promise<any>;
  }

  // ---- Worker entrypoint (service) ----

  export class WorkerEntrypoint<Env = any> {
    protected env: Env;

    // Support both (request) and (request, env, ctx) forms
    fetch(
      request: Request,
      env?: Env,
      ctx?: ExecutionContext
    ): Promise<Response> | Response;
  }

  // ---- Bindings used by this project ----

  // Workers AI binding
  export interface Ai {
    run(model: string, input: any): Promise<any>;
  }

  // D1 Database binding (minimal)
  export type D1PreparedStatement = {
    bind(...params: any[]): D1PreparedStatement;
    first<T = any>(): Promise<T | null>;
    all<T = any>(): Promise<{ results: T[] }>;
    run(): Promise<any>;
  };

  export interface D1Database {
    prepare<T = any>(sql: string): D1PreparedStatement;
    batch(statements: D1PreparedStatement[]): Promise<any[]>;
  }

  // R2 Bucket binding (minimal)
  export interface R2PutOptions {
    httpMetadata?: {
      contentType?: string;
      contentLanguage?: string;
      contentDisposition?: string;
      contentEncoding?: string;
      cacheControl?: string;
      cacheExpiry?: string | Date;
      lastModified?: string | Date;
    };
    customMetadata?: Record<string, string>;
  }

  export interface R2PutResult {
    etag?: string;
    size?: number;
    httpMetadata?: Record<string, string>;
    customMetadata?: Record<string, string>;
  }

  export interface R2Bucket {
    put(
      key: string,
      value:
        | string
        | ArrayBuffer
        | ArrayBufferView
        | Blob
        | ReadableStream
        | null,
      options?: R2PutOptions
    ): Promise<R2PutResult | null>;

    get(
      key: string
    ): Promise<ReadableStream | Blob | ArrayBuffer | null>;
    head?(key: string): Promise<{ etag?: string; size?: number } | null>;
    delete?(keys: string | string[]): Promise<void>;
  }
}

// ---- Runtime globals augmentations (minimal) ----

declare global {
  interface ExecutionContext {
    waitUntil(promise: Promise<any>): void;
    passThroughOnException?(): void;
  }

  // Removed Response constructor augmentation to avoid conflicts with lib.dom

  interface Crypto {
    randomUUID(): string;
    readonly subtle: SubtleCrypto;
  }
}

export { };
