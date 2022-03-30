import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AtJwtStrategy } from './strategies/at-strategy';
import { RtJwtStrategy } from './strategies/rt-strategy';

@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, AtJwtStrategy, RtJwtStrategy],
})
export class AuthModule {}
