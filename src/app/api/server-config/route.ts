/* eslint-disable no-console */
import { NextRequest, NextResponse } from 'next/server';
import { getConfig } from '@/lib/config';

// —— 禁用一切缓存/静态化 —— //
export const runtime = 'edge';
export const revalidate = 0;
export const dynamic = 'force-dynamic';
export const fetchCache = 'force-no-store';

type SanitizedUser = { username: string; role?: string; banned: boolean };

function sanitizeUsers(input: unknown): SanitizedUser[] {
  const arr = Array.isArray(input) ? input : [];
  return arr
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .map((u: any) => {
      const username: string = String(u?.username ?? u?.name ?? u?.userName ?? '').trim();
      const role: string | undefined = u?.role ?? u?.userRole ?? undefined;
      const raw = u?.banned ?? u?.disabled ?? u?.status ?? false;
      const banned =
        raw === true ||
        raw === 1 ||
        raw === '1' ||
        (typeof raw === 'string' && ['true', 'banned', 'disabled'].includes(raw.toLowerCase()));
      return { username, role, banned };
    })
    .filter((u) => u.username);
}

export async function GET(request: NextRequest) {
  try {
    console.log('server-config called:', request.url);

    const cfg = await getConfig();
    // 用 any 规避 AdminConfig 上不存在 Users 的类型报错
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const anyCfg: any = cfg as any;

    const rawUsers =
      anyCfg?.UserConfig?.Users ??
      anyCfg?.Users ??
      anyCfg?.users ??
      [];

    const users = sanitizeUsers(rawUsers);

    const payload = {
      SiteName: anyCfg?.SiteConfig?.SiteName ?? 'Site',
      StorageType: process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage',
      // middleware 会从这里读取封禁清单
      UserConfig: { Users: users }, // 仅暴露 username/role/banned
      updatedAt: Date.now(),
    };

    return NextResponse.json(payload, {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        Pragma: 'no-cache',
        Expires: '0',
        'CDN-Cache-Control': 'no-store',
        'Vercel-CDN-Cache-Control': 'no-store',
        'Surrogate-Control': 'no-store',
      },
    });
  } catch (err) {
    console.error('server-config error:', err);
    // 让 middleware 感知失败 → 走 fail-closed
    return NextResponse.json(
      { error: 'server-config unavailable' },
      {
        status: 503,
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
          Pragma: 'no-cache',
          Expires: '0',
          'CDN-Cache-Control': 'no-store',
          'Vercel-CDN-Cache-Control': 'no-store',
          'Surrogate-Control': 'no-store',
        },
      }
    );
  }
}
