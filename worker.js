// Cloudflare Worker — download proxy
//
// KYUN chahiye:
//  1. Instagram ka CDN "Content-Disposition: attachment" nahi bhejta, isliye
//     video download hone ki jagah browser me khul jaata hai.
//  2. CDN CORS allow nahi karta, to frontend se fetch+blob bhi kaam nahi karega.
//  3. Bytes WordPress ya Vercel se proxy karoge to bandwidth bill phat jayega
//     (5 MB x 5000/day = ~750 GB/month). Workers ka egress free hai.
//
// Deploy: GitHub repo bana kar Cloudflare me "Import a Git repository"
// Secret: Worker → Settings → Variables and Secrets → DOWNLOAD_SECRET
//         (wahi value jo Vercel me hai)

const ALLOWED_HOSTS = /(^|\.)(cdninstagram\.com|fbcdn\.net)$/i;

const enc = new TextEncoder();

/** Vercel ke createHmac('sha256', secret).update(`${url}|${exp}`) ka exact match */
async function expectedSig(secret, url, exp) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(`${url}|${exp}`));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Timing-safe compare — warna signature byte-by-byte guess ki ja sakti hai */
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method not allowed', { status: 405 });
    }
    if (!env.DOWNLOAD_SECRET) {
      return new Response('Worker setup adhoora hai — DOWNLOAD_SECRET missing', { status: 500 });
    }

    const { searchParams } = new URL(request.url);
    const target = searchParams.get('u');
    const exp = searchParams.get('exp');
    const sig = searchParams.get('sig') || '';
    const filename = (searchParams.get('name') || 'instagram.mp4').replace(/[^\w.\-]/g, '_');

    // inline=1 -> page par dikhane ke liye (thumbnail, video player).
    // Iske bina browser har preview par download shuru kar deta.
    const inline = searchParams.get('inline') === '1';

    if (!target || !exp) return new Response('Missing parameters', { status: 400 });

    // exp Instagram ke apne link ki expiry hoti hai — Vercel wahi bhejta hai
    // taki signature har baar same rahe aur CDN cache me stale na ho.
    if (!/^\d+$/.test(exp) || Number(exp) * 1000 < Date.now()) {
      return new Response('Link expire ho gaya — page refresh karke dobara try karo', { status: 410 });
    }

    if (!safeEqual(await expectedSig(env.DOWNLOAD_SECRET, target, exp), sig)) {
      return new Response('Invalid signature', { status: 403 });
    }

    // SSRF guard — sirf Instagram/Facebook CDN, warna ye kisi bhi cheez ka proxy ban jaata
    let t;
    try { t = new URL(target); } catch { return new Response('Bad URL', { status: 400 }); }
    if (t.protocol !== 'https:' || !ALLOWED_HOSTS.test(t.hostname)) {
      return new Response('Host not allowed', { status: 403 });
    }

    const range = request.headers.get('range');
    const upstream = await fetch(t.toString(), {
      method: request.method,
      headers: {
        'User-Agent': 'Mozilla/5.0',
        ...(range ? { Range: range } : {}),
      },
      // wahi file dobara maangi jaye to Cloudflare ke edge se jayegi, Instagram tak nahi
      cf: { cacheEverything: true, cacheTtl: 3600 },
    });

    if (!upstream.ok && upstream.status !== 206) {
      return new Response('Instagram ka link expire ho gaya — page refresh karo', { status: 502 });
    }

    const headers = new Headers();
    headers.set('Content-Type', upstream.headers.get('content-type') || 'application/octet-stream');
    headers.set('Content-Disposition', inline ? 'inline' : `attachment; filename="${filename}"`);
    headers.set('Cache-Control', 'public, max-age=3600');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Access-Control-Allow-Origin', '*');
    for (const h of ['content-length', 'content-range', 'accept-ranges']) {
      const v = upstream.headers.get(h);
      if (v) headers.set(h, v);
    }

    return new Response(request.method === 'HEAD' ? null : upstream.body, {
      status: upstream.status,
      headers,
    });
  },
};
