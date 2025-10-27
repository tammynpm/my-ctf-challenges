import { Injectable, Logger } from '@nestjs/common';
import { isAbsolute, join } from 'path';
import { existsSync, writeFileSync, readFileSync } from 'fs';

@Injectable()
export class FlagService {
  private readonly logger = new Logger(FlagService.name);
  private currentPath: string;
  private readonly persistPath = join(process.cwd(), 'real_flag.txt');

  constructor() {
    // load persisted path if present, otherwise default to assets/flag.png
    try {
      if (existsSync(this.persistPath)) {
        const p = readFileSync(this.persistPath, 'utf8').trim();
        if (p) {
          // Resolve relative paths to absolute
          this.currentPath = isAbsolute(p) ? p : join(process.cwd(), p);
        }
      }
    } catch (e) {
      this.logger.warn('Could not read persist path: ' + e.message);
    }
    if (!this.currentPath) {
      this.currentPath = join(process.cwd(), 'assets', 'flag.png');
    }
  }

  get(): string {return this.currentPath;}

  set(newPath: string): boolean {
    const resolved = isAbsolute(newPath) ? newPath : join(process.cwd(), newPath);

    if (!existsSync(resolved)) {
      throw new Error('file-not-found');}

    this.currentPath = resolved;

    const cwd = process.cwd();
    let toPersist = resolved;

    if (resolved.startsWith(cwd + '/')) {
      toPersist = resolved.slice(cwd.length + 1);
    }

    // persist chosen path (optional)
    try {
      writeFileSync(this.persistPath, toPersist, 'utf8');
    } catch (e) {
      this.logger.warn('Could not persist flag path: ' + e.message);
    }

    this.logger.log(`Flag updated to ${resolved}`);
    return true;
  }
}
