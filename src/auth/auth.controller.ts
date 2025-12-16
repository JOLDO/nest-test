import { Body, Controller, Get, Post, Req, Res, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import type { Request, Response } from "express";
import { JwtService } from "@nestjs/jwt";

@Controller("auth")
export class AuthController {
  constructor(private auth: AuthService, private jwt: JwtService) {}

  @Post("signup")
  signup(@Body() body: { email: string; password: string; name?: string | null }) {
    return this.auth.signup(body.email, body.password, body.name ?? null);
  }

  @Post("login")
  async login(@Body() body: { email: string; password: string }, @Res({ passthrough: true }) res: Response) {
    const { token, user } = await this.auth.login(body.email, body.password);

    res.cookie("access_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // https면 true
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return user;
  }

  @Post("logout")
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie("access_token", { path: "/" });
    return { ok: true };
  }

  @Get("me")
  async me(@Req() req: Request) {
    const token = req.cookies?.access_token;
    if (!token) throw new UnauthorizedException("로그인이 필요합니다.");

    try {
      const payload = await this.jwt.verifyAsync(token);
      return this.auth.me(payload.sub);
    } catch {
      throw new UnauthorizedException("로그인이 필요합니다.");
    }
  }
}
