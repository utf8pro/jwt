import {jwtVerify, SignJWT, type JWTPayload} from "jose"

export type TJwt = {
  sign<T extends JWTPayload>(payload: T): Promise<string>
  verify<T extends JWTPayload>(token: string): Promise<T>
}

export type TJwtPayload = JWTPayload

export function createJwt(key: string): TJwt {
  const encoded = new TextEncoder().encode(key)
  return {
    sign: async <T extends JWTPayload>(payload: T) => sign(payload, encoded),
    verify: async <T extends JWTPayload>(token: string): Promise<T> => verify(token, encoded),
  }
}

export async function signJwt<T extends JWTPayload>(payload: T, key: string): Promise<string> {
  return await sign<T>(payload, new TextEncoder().encode(key))
}

export async function verifyJwt<T extends JWTPayload>(token: string, key: string): Promise<T> {
  return await verify<T>(token, new TextEncoder().encode(key))
}

async function sign<T extends JWTPayload>(payload: T, key: Uint8Array): Promise<string> {
  return await new SignJWT(payload)
    .setProtectedHeader({alg: "HS256"})
    .setIssuedAt()
    .sign(key)
}

async function verify<T extends JWTPayload>(token: string, key: Uint8Array): Promise<T> {
  const jwt = await jwtVerify(token, key)
  return jwt.payload as T
}

