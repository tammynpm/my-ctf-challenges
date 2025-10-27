import { Controller, Get, Res, Header } from '@nestjs/common';
import type { Response } from 'express';
import { FlagService } from './flag.service';

@Controller()
export class FlagController {
  constructor(private readonly flagService: FlagService) {}

  @Get('get-flag')
  @Header('Content-Type', 'application/octet-stream')
  @Header('Content-Disposition', 'attachment; filename="flag.png"')
  @Header('Cache-Control', 'no-store')
  getFlag(@Res() res: Response) {
    const filePath = this.flagService.get(); //returns absolute path
    return res.sendFile(filePath);
  }
}