import { Logger } from '@nestjs/common';
import type { BastionLogger } from '../core/types.js';

export function nestLogger(context: string): BastionLogger {
  const logger = new Logger(context);
  return {
    warn: (m) => logger.warn(m),
    error: (m) => logger.error(m),
    log: (m) => logger.log(m),
  };
}
