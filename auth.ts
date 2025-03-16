import NextAuth from "next-auth"
import {encode} from "next-auth/jwt"


import Apple from "next-auth/providers/apple"
// import Atlassian from "next-auth/providers/atlassian"
import Auth0 from "next-auth/providers/auth0"
import AzureB2C from "next-auth/providers/azure-ad-b2c"
import BankIDNorway from "next-auth/providers/bankid-no"
import BoxyHQSAML from "next-auth/providers/boxyhq-saml"
import Cognito from "next-auth/providers/cognito"
import Coinbase from "next-auth/providers/coinbase"
import Discord from "next-auth/providers/discord"
import Dropbox from "next-auth/providers/dropbox"
import Facebook from "next-auth/providers/facebook"
import GitHub from "next-auth/providers/github"
import GitLab from "next-auth/providers/gitlab"
import Google from "next-auth/providers/google"
import Hubspot from "next-auth/providers/hubspot"
import Keycloak from "next-auth/providers/keycloak"
import LinkedIn from "next-auth/providers/linkedin"
import MicrosoftEntraId from "next-auth/providers/microsoft-entra-id"
import Netlify from "next-auth/providers/netlify"
import Okta from "next-auth/providers/okta"
import Passage from "next-auth/providers/passage"
import Passkey from "next-auth/providers/passkey"
import Pinterest from "next-auth/providers/pinterest"
import Reddit from "next-auth/providers/reddit"
import Slack from "next-auth/providers/slack"
import Salesforce from "next-auth/providers/salesforce"
import Spotify from "next-auth/providers/spotify"
import Twitch from "next-auth/providers/twitch"
import Twitter from "next-auth/providers/twitter"
import Vipps from "next-auth/providers/vipps"
import WorkOS from "next-auth/providers/workos"
import Zoom from "next-auth/providers/zoom"
import { createStorage } from "unstorage"
import memoryDriver from "unstorage/drivers/memory"
import vercelKVDriver from "unstorage/drivers/vercel-kv"
import { UnstorageAdapter } from "@auth/unstorage-adapter"
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

const options = {
  pkceCodeVerifier: {
    name: `authjs.pkce.code_verifier`,
      options: {
      httpOnly: true,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 15, // 15 minutes in seconds
    },
  },
}

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
  console.log(array)
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

export const { handlers, auth, signIn, signOut } = NextAuth({
  debug: false,
  theme: { logo: "https://authjs.dev/img/logo-sm.png" },
  providers: [
    Keycloak
  ],
  session: { strategy: "jwt" },
  callbacks: {
    async authorized({ request, auth }) {
      const bb = await generatePKCE();
      console.log(bb)



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
          salt: "authjs.pkce.code_verifier",
          token: { value: codeVerifier},
          maxAge: 900,
          secret: '30a5185b44a7426d1684500b9fdea7b59dc76d967c6b01e5a7bff08972acb3f3'
        })

        resp.cookies.set(
          "authjs.pkce.code_verifier",
          codeVerifierEncoded,
          {
            maxAge: 900,
            path: '/',
            httpOnly: true,
            sameSite: "lax",
          }
        )

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
