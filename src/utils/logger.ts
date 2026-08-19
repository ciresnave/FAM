// Structured Logger for FAM
//
// Provides consistent, structured logging with levels and context.

// ============================================================================
// Log Levels
// ============================================================================

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

// ============================================================================
// Logger
// ============================================================================

export class Logger {
  private level: LogLevel;
  private context: string;
  
  constructor(context: string, level?: LogLevel) {
    this.context = context;
    this.level = level ?? (process.env.FAM_LOG_LEVEL
      ? LogLevel[process.env.FAM_LOG_LEVEL.toUpperCase() as keyof typeof LogLevel] ?? LogLevel.INFO
      : LogLevel.INFO);
  }
  
  debug(message: string, data?: Record<string, unknown>): void {
    if (this.level <= LogLevel.DEBUG) {
      this.log('DEBUG', message, data);
    }
  }
  
  info(message: string, data?: Record<string, unknown>): void {
    if (this.level <= LogLevel.INFO) {
      this.log('INFO', message, data);
    }
  }
  
  warn(message: string, data?: Record<string, unknown>): void {
    if (this.level <= LogLevel.WARN) {
      this.log('WARN', message, data);
    }
  }
  
  error(message: string, error?: unknown, data?: Record<string, unknown>): void {
    if (this.level <= LogLevel.ERROR) {
      const errorData: Record<string, unknown> = { ...data };
      if (error instanceof Error) {
        errorData.error = error.message;
        errorData.stack = error.stack;
      } else if (error) {
        errorData.error = String(error);
      }
      this.log('ERROR', message, errorData);
    }
  }
  
  private log(level: string, message: string, data?: Record<string, unknown>): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      context: this.context,
      message,
      ...data,
    };
    
    // Use stderr for MCP compatibility (stdout is reserved for MCP protocol)
    if (level === 'ERROR' || level === 'WARN') {
      console.error(JSON.stringify(entry));
    } else {
      console.error(JSON.stringify(entry));
    }
  }
  
  /**
   * Create a child logger with additional context.
   */
  child(context: string): Logger {
    return new Logger(`${this.context}:${context}`, this.level);
  }
}

// ============================================================================
// Default Logger
// ============================================================================

export const logger = new Logger('fam');
