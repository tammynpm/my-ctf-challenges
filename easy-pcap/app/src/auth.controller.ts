// src/auth.controller.ts
import { Controller, Get, Post, Body, Res } from '@nestjs/common';
import type { Response } from 'express';
import { randomBytes } from 'crypto';
import { sessions } from './session.store';

@Controller()
export class AuthController {
  @Get('login')
  loginForm(@Res() res: Response) {
    // very small form (urlencoded)
    res.send(`
      <html><body>
        <h2>Login</h2>
        <form method="POST" action="/login">
          <label>Username: <input name="username"/></label><br/>
          <label>Password: <input name="password" type="password"/></label><br/>
          <button type="submit">Login</button>
        </form>
      </body></html>
    `);
  }

  @Post('login')
  async login(@Body() body: any, @Res() res: Response) {
    const user = body?.username ?? '';
    const pass = body?.password ?? '';
    const OK =
      user === (process.env.ADMIN_USER || 'IKillVibes') &&
      pass === (process.env.ADMIN_PASS || 'IKillVibes');

    if (!OK) {
      return res.status(401).send('Invalid credentials');
    }

    // create session id, store it, set cookie
    const sid = randomBytes(12).toString('hex');
    sessions.set(sid, user);

    // set cookie (HttpOnly so not visible to JS) — NO Secure flag so it's visible in HTTP PCAP (CTF)
    res.cookie('session', sid, { httpOnly: true, path: '/' });
    return res.redirect('/admin/02358-setflag/hidden');
  }
}
