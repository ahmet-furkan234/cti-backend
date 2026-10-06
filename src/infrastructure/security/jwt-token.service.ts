import { createHash, randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import { inject, injectable } from "inversify";
import { TYPES } from "../../shared/tokens.js";
import type {
  AccessTokenClaims,
  ITokenService,
} from "../../application/ports/ports.js";
import type { EnvConfig } from "../common/env.config.js";

//TODO : Ayrı dosyaya taşıacak
function toSeconds(value: string): number {
  const m = /^(\d+)\s*([smhd])$/.exec(value);
  if (!m) return 900;
  const n = Number(m[1]);
  return n * { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as "s" | "m" | "h" | "d"];
}

@injectable()
export class JwtTokenService implements ITokenService {
  private readonly ttl: number;

  constructor(@inject(TYPES.EnvConfig) private readonly config: EnvConfig) {
    this.ttl = toSeconds(config.JWT_ACCESS_EXPIRES_IN);
  }

  signAccessToken(userId: string) {
    const token = jwt.sign({}, this.config.JWT_ACCESS_SECRET, {
      subject: userId,
      expiresIn: this.ttl,
      algorithm: "HS256", //TODO Constant' oluştup taşıcanak genel
    });
    return { token, expiresInSeconds: this.ttl };
  }

  verifyAccessToken(token: string): AccessTokenClaims | null {
    try {
      const payload = jwt.verify(token, this.config.JWT_ACCESS_SECRET, {
        algorithms: ["HS256"],
      }); //TODO Constant' oluştup taşıcanak genel HS256
      if (typeof payload === "string" || !payload.sub) return null;
      return { sub: payload.sub };
    } catch {
      return null;
    }
  }

  generateOpaqueToken() {
    const token = randomBytes(48).toString("base64url"); //TODO Constant' oluştup taşıcanak genel base64url
    return { token, hash: this.hashOpaqueToken(token) };
  }

  hashOpaqueToken(token: string): string {
    return createHash("sha256").update(token).digest("hex"); //TODO Constant' oluştup taşıcanak genel sha256
  }
}
