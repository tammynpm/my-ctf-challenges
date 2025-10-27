// src/session.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { sessions } from './session.store';

@Injectable()
export class SessionGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const res = ctx.switchToHttp().getResponse();
    const sid = req.cookies && req.cookies.session;
    
    if (!sid || !sessions.has(sid)) {
      // Redirect to login instead of returning 403
      res.redirect('/login');
      return false;
    }
    
    return true;
  }
}
