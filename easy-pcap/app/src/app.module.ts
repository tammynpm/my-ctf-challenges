import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { FlagController } from './flag.controller';
import { FlagService } from './flag.service';
import { AdminGuard } from './admin.guard';
import { AdminController } from './admin.controller';
import { AuthController } from './auth.controller';
import { SessionGuard } from './session.guard';
@Module({
  imports: [],
  controllers: [AppController, FlagController, AdminController, AuthController],
  providers: [AppService, FlagService, SessionGuard],
})
export class AppModule {}
