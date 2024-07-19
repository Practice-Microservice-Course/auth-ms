import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { NatsModule } from 'src/transports/nats.module';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    NatsModule,
    JwtModule.register({
      global: true,
      secret: envs.JWT_SECRET,
      signOptions: { expiresIn: '60s' },
    }),
  ],
})
export class AuthModule {}
