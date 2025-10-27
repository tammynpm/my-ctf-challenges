// src/admin.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const token = req.headers['x-admin-token'];
    const secret = process.env.ADMIN_TOKEN || 'changeme';
    return !!token && token === secret;
  }
}


