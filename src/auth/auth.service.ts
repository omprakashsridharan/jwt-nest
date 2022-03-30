import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './auth.types';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(authDto: AuthDto): Promise<Tokens> {
    const newUser = await this.prisma.user.create({
      data: {
        email: authDto.email,
        hash: await this.hashData(authDto.password),
      },
    });
    return await this.generateTokens(newUser);
  }

  async generateTokens(user: User): Promise<Tokens> {
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    return tokens;
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async updateRtHash(userId: number, rt: string) {
    const hashedRt = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt,
      },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const accessToken = await this.jwtService.signAsync(
      {
        sub: userId,
        email,
      },
      {
        secret: 'at-secret',
        expiresIn: 60 * 15,
      },
    );
    const refreshToken = await this.jwtService.signAsync(
      {
        sub: userId,
        email,
      },
      {
        secret: 'rt-secret',
        expiresIn: 60 * 60 * 24 * 7,
      },
    );
    return {
      accessToken,
      refreshToken,
    };
  }

  async signinLocal(authDto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: authDto.email,
      },
    });
    if (!user) throw new ForbiddenException('Access Denied');
    const passwordMatches = await bcrypt.compare(authDto.password, user.hash);
    if (!passwordMatches) throw new ForbiddenException('Access Denied');
    return await this.generateTokens(user);
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refresh(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');
    const rtMatches = await bcrypt.compare(rt, user.hashedRt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');
    return await this.generateTokens(user);
  }
}
