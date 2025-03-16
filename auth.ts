import NextAuth from "next-auth"
import {encode} from "next-auth/jwt"
import Keycloak from "next-auth/providers/keycloak"

import { createStorage } from "unstorage"
import memoryDriver from "unstorage/drivers/memory"
import vercelKVDriver from "unstorage/drivers/vercel-kv"
import {NextResponse} from "next/server";

const storage = createStorage({
  driver: process.env.VERCEL
    ? vercelKVDriver({
        url: process.env.AUTH_KV_REST_API_URL,
        token: process.env.AUTH_KV_REST_API_TOKEN,
        env: false,
      })
    : memoryDriver(),
})

async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = generateRandomString(128);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  return { codeVerifier, codeChallenge };
}

// ✅ 난수 기반 `code_verifier` 생성 (128자 랜덤 문자열)
function generateRandomString(length: number): string {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const array = new Uint8Array(length);
  crypto.getRandomValues(array); // Web Crypto API 사용
  return Array.from(array, (byte) => charset[byte % charset.length]).join('');
}

// ✅ SHA-256 해싱 후 Base64 URL 인코딩하여 `code_challenge` 생성
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

// ✅ Base64 URL-safe 인코딩
function base64UrlEncode(buffer: Uint8Array): string {
  // @ts-ignore
  return btoa(String.fromCharCode(...buffer))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

const useSecureCookies = Boolean(process.env.AUTH_URL?.startsWith('https'))
const cookiePrefix = useSecureCookies ? "__Secure-" : "";

export const { handlers, auth, signIn, signOut } = NextAuth({
  debug: false,
  theme: { logo: "https://authjs.dev/img/logo-sm.png" },
  providers: [
    Keycloak
  ],
  session: { strategy: "jwt" },
  callbacks: {
    async redirect({url, baseUrl}) {
      /* 로그인이 성공 (oauth2 로그인 성공) 하면 무조건 이전에 머물렀던 페이지로 감
      * 보호되는 URL 이라면 보호되는 URL 로 가고
      * public url 은 보호되는 홈 (예를들면 / 경로) 로 가도록 구현 하면 될것같다.
      * */
      return url;
    },
    async authorized({ request, auth }) {
      const { pathname } = request.nextUrl
      if (pathname === "/middleware-example" && !auth) {
        const { codeChallenge, codeVerifier} = await generatePKCE()
        const oauth2Params = {
          "response_type": "code",
          "client_id": "web-client",
          "redirect_uri": "http://localhost:3000/api/auth/callback/keycloak",
          "code_challenge": codeChallenge,
          "code_challenge_method": "S256",
          "scope": "openid profile email"
        } as Record<string, string>
        const url = new URL('https://auth.overpowerman.click/realms/myrealm/protocol/openid-connect/auth');
        Object.keys(oauth2Params).map(p => url.searchParams.set(p, oauth2Params[p]))
        const resp = NextResponse.redirect(url)

        const codeVerifierEncoded = await encode<{value: string}>({
          salt: `${cookiePrefix}authjs.pkce.code_verifier`,
          token: { value: codeVerifier},
          maxAge: 900,
          secret: '30a5185b44a7426d1684500b9fdea7b59dc76d967c6b01e5a7bff08972acb3f3'
        })

        resp.cookies.set(
          `${cookiePrefix}authjs.pkce.code_verifier`,
          codeVerifierEncoded,
          {
            maxAge: 900,
            path: '/',
            httpOnly: true,
            sameSite: "lax",
          }
        )
        // return false
        return resp;
      }
      return true
    },
    jwt({ token, trigger, session, account }) {
      if (trigger === "update") token.name = session.user.name
      if (account?.provider === "keycloak") {
        return { ...token, accessToken: account.access_token }
      }
      return token
    },
    async session({ session, token }) {
      if (token?.accessToken) session.accessToken = token.accessToken

      return session
    },
  },
  experimental: { enableWebAuthn: true },
})

declare module "next-auth" {
  interface Session {
    accessToken?: string
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string
  }
}
