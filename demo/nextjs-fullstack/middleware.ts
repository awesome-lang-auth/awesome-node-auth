/**
 * Next.js Edge Middleware — protects /dashboard and other authenticated routes.
 *
 * Reads the HttpOnly accessToken cookie and verifies it with the Web Crypto API
 * (Node.js `crypto` / `jsonwebtoken` are not available in the Edge Runtime):
 * the HMAC signature, the expiry, and that it is a session token.
 */

import { NextRequest, NextResponse } from 'next/server';

export const config = {
  matcher: ['/dashboard/:path*'],
};

function base64UrlDecode(input: string) {
  return Uint8Array.from(
    atob(input.replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0),
  );
}

export async function middleware(request: NextRequest): Promise<NextResponse> {
  const token = request.cookies.get('accessToken')?.value;

  if (!token) {
    return NextResponse.redirect(new URL('/', request.url));
  }

  try {
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const enc  = new TextEncoder();
    const key  = await crypto.subtle.importKey(
      'raw',
      enc.encode(process.env.ACCESS_TOKEN_SECRET ?? 'demo-access-secret-change-in-production'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const sig  = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, sig, enc.encode(`${headerB64}.${payloadB64}`));
    if (!valid) throw new Error('Invalid signature');

    // A valid signature is not enough: the token must be unexpired, and must
    // not carry a `purpose` claim, which marks tokens that are not sessions
    // (the 2FA step-up token and the admin console token).
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) throw new Error('Expired');
    if (payload.purpose !== undefined) throw new Error('Not a session token');
    return NextResponse.next();
  } catch {
    return NextResponse.redirect(new URL('/', request.url));
  }
}
