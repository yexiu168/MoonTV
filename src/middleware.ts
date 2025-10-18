/* eslint-disable no-console */
import { NextRequest, NextResponse } from 'next/server';
import { getAuthInfoFromCookie } from '@/lib/auth';

const LOWER = (s?: string) => (s ?? '').trim().toLowerCase();

function shouldSkip(pathname: string) {
  return (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon') ||
    pathname === '/robots.txt' ||
    pathname.startsWith('/manifest') ||
    pathname.startsWith('/icons') ||
    pathname.startsWith('/sitemap') ||
    pathname.startsWith('/login') ||
    pathname.startsWith('/warning') ||
    pathname.startsWith('/api/login') ||
    pathname.startsWith('/api/register') ||
    pathname.startsWith('/api/logout') ||
    pathname.startsWith('/api/cron') ||
    pathname.startsWith('/api/server-config')
  );
}

function clearAuth(res: NextResponse, req: NextRequest) {
  const expire = new Date(0);
  res.cookies.set('auth', '', { path: '/', expires: expire, sameSite: 'lax', httpOnly: true });
  const host = req.nextUrl.hostname;
  if (host.includes('.')) {
    res.cookies.set('auth', '', { path: '/', domain: host, expires: expire, sameSite: 'lax', httpOnly: true });
  }
}

function block(req: NextRequest, isApi: boolean) {
  const res = isApi
    ? new NextResponse('Forbidden', { status: 403 })
    : NextResponse.redirect(new URL('/login', req.url));
  clearAuth(res, req);
  return res;
}

// 强制每次取最新封禁清单（避免 CDN/ISR 缓存）
async function getBannedSet(req: NextRequest): Promise<Set<string>> {
  const url = new URL('/api/server-config', req.url);
  url.searchParams.set('ts', String(Date.now()));
  const res = await fetch(url.toString(), {
    cache: 'no-store',
    headers: {
      'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
      Pragma: 'no-cache',
    },
  });
  if (!res.ok) throw new Error(`server-config ${res.status}`);
  const data = await res.json();

  const users = data?.UserConfig?.Users ?? data?.Users ?? data?.users ?? [];
  const set = new Set<string>();
  for (const u of users as Array<any>) {
    const name = LOWER((u?.username ?? u?.name ?? u?.userName) as string | undefined);
    const raw = (u as any)?.banned ?? (u as any)?.disabled ?? (u as any)?.status;
    const banned =
      raw === true || raw === 1 || raw === '1' ||
      (typeof raw === 'string' && ['true', 'banned', 'disabled'].includes(raw.toLowerCase()));
    if (name && banned) set.add(name);
  }
  return set;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (shouldSkip(pathname)) return NextResponse.next();

  if (!process.env.PASSWORD) {
    return NextResponse.redirect(new URL('/warning', request.url));
  }

  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';
  const isApi = pathname.startsWith('/api');
  const auth = getAuthInfoFromCookie(request);
  if (!auth) return block(request, isApi);

  // 1) localstorage：全站口令模式
  if (storageType === 'localstorage') {
    if (auth.password !== process.env.PASSWORD) return block(request, isApi);

    // 若 Cookie 带了 username，顺带做一次封禁校验（容错）
    if (auth.username) {
      try {
        const banned = await getBannedSet(request);
        if (banned.has(LOWER(auth.username))) return block(request, isApi);
      } catch {
        // 更安全：拿不到配置则拦截
        return block(request, isApi);
      }
    }
    return NextResponse.next();
  }

  // 2) 多用户模式：签名 + 封禁
  if (!auth.username || !auth.signature) return block(request, isApi);

  const ok = await verifySignature(auth.username, auth.signature, process.env.PASSWORD!);
  if (!ok) return block(request, isApi);

  try {
    const banned = await getBannedSet(request);
    if (banned.has(LOWER(auth.username))) return block(request, isApi);
  } catch {
    return block(request, isApi); // fail-closed
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|robots.txt|manifest.json|icons/|login|warning|api/server-config|api/login|api/register|api/logout|api/cron).*)',
  ],
};

// —— 本地实现：HMAC-SHA256 验签（Edge Runtime 可用）——
async function verifySignature(data: string, signature: string, secret: string): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBytes = new Uint8Array((signature.match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16)));
    return await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
  } catch (e) {
    console.error('verifySignature error:', e);
    return false;
  }
}
