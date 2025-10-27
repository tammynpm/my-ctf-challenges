// src/admin.controller.ts
import { Controller, Get, Res, UseGuards, Header, Post, UploadedFile, UseInterceptors } from '@nestjs/common';
import { FlagService } from './flag.service';
import { SessionGuard } from './session.guard';
import type { Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import type {File as MulterFile} from 'multer';
import { join } from 'path';

@Controller('admin/02358-setflag')
@UseGuards(SessionGuard)
export class AdminController {
  constructor(private flagService: FlagService) {}

  @Get('hidden')
  hidden(@Res() res: Response) {
    // simple page with a button that GETs /flag
    res.send(`
      <html><body>
        <h1>Admin Console</h1>
        <form action="/admin/02358-setflag/upload-flag" method="POST" enctype="multipart/form-data">
          <input type="file" name="file" />
          <button type="submit">Upload new flag</button>
        </form>
        <hr/>
        <form action="/admin/02358-setflag/flag" method="GET">
          <button type="submit">Get Flag</button>
        </form>
      </body></html>
    `);
  }

  @Post('upload-flag')
  @UseInterceptors(FileInterceptor('file', {
    storage: diskStorage({
      destination: './uploads',
      filename: (req, file, cb) =>
        cb(null, `${Date.now()}-${(file as any).originalname || 'upload.bin'}`),
    }),
  }))

  async upload(@UploadedFile() file: MulterFile) {
    return { ok: true, filename: (file as any).filename, path: (file as any).path };
  }

  @Get('flag')
  @Header('Content-Type', 'text/plain')
  @Header('Content-Disposition', 'inline')
  getRealFlag(@Res() res: Response) {
    const real = join(process.cwd(), 'assets', 'real_flag.txt');  // <- serve secret here
    return res.sendFile(real);
  }

}


