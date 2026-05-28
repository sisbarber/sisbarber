/**
 * ═══════════════════════════════════════════════════════
 *  SIS BARBER SHOP — CLOUDFLARE WORKER
 *  Security headers, rate limiting, bot protection
 *  Deploy: Cloudflare Dashboard → Workers & Pages → Create Worker → paste this
 * ═══════════════════════════════════════════════════════
 */

// ── Rate limit config ────────────────────────────────────
// Max booking form submissions per IP per window
const RATE_LIMIT_MAX      = 5;    // max 5 submissions
const RATE_LIMIT_WINDOW   = 3600; // per hour (seconds)

// ── Allowed origins ──────────────────────────────────────
const ALLOWED_ORIGINS = [
    'https://sisbarber.com',
    'https://www.sisbarber.com',
];

// ════════════════════════════════════════════════════════
//  MAIN HANDLER
// ════════════════════════════════════════════════════════
export default {
    async fetch(request, env, ctx) {
        const url      = new URL(request.url);
        const origin   = request.headers.get('Origin') || '';
        const ip       = request.headers.get('CF-Connecting-IP') || 'unknown';
        const ua       = request.headers.get('User-Agent') || '';
        const country  = request.headers.get('CF-IPCountry') || 'XX';

        // ── 1. Block obviously malicious bots ───────────────
        const badBots = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'python-requests/2.', 'curl/7.'];
        if (badBots.some(b => ua.toLowerCase().includes(b))) {
            return new Response('Forbidden', { status: 403 });
        }

        // ── 2. Block high-risk countries (edit as needed) ───
        // Remove any you don't want to block
        const BLOCKED_COUNTRIES = []; // e.g. ['CN', 'RU', 'KP'] — left empty by default

        if (BLOCKED_COUNTRIES.includes(country)) {
            return new Response('Service not available in your region.', { status: 451 });
        }

        // ── 3. Rate limit on /api/book or form POSTs ────────
        if (request.method === 'POST') {
            const rateLimitKey = `rl:${ip}`;

            if (env.SIS_KV) {
                const current = parseInt(await env.SIS_KV.get(rateLimitKey) || '0');
                if (current >= RATE_LIMIT_MAX) {
                    return new Response(
                        JSON.stringify({ error: 'Too many requests. Please try again later.' }),
                        {
                            status: 429,
                            headers: {
                                'Content-Type': 'application/json',
                                'Retry-After': String(RATE_LIMIT_WINDOW),
                            }
                        }
                    );
                }
                ctx.waitUntil(
                    env.SIS_KV.put(rateLimitKey, String(current + 1), { expirationTtl: RATE_LIMIT_WINDOW })
                );
            }
        }

        // ── 4. Fetch the actual page ─────────────────────────
        const response = await fetch(request);

        // ── 5. Clone and inject security headers ────────────
        const newHeaders = new Headers(response.headers);

        // Strict Transport Security — forces HTTPS for 1 year
        newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

        // Content Security Policy — whitelist only what we use
        newHeaders.set('Content-Security-Policy', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://www.tiktok.com https://www.tiktok.com",
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com",
            "img-src 'self' data: https://images.unsplash.com https://www.tiktok.com",
            "frame-src https://www.tiktok.com",
            "connect-src 'self' https://api.emailjs.com https://api.web3forms.com",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "upgrade-insecure-requests",
        ].join('; '));

        // Clickjacking protection
        newHeaders.set('X-Frame-Options', 'SAMEORIGIN');

        // MIME sniffing protection
        newHeaders.set('X-Content-Type-Options', 'nosniff');

        // Referrer policy — don't leak URL to third parties
        newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Permissions — disable access to camera, mic, location etc.
        newHeaders.set('Permissions-Policy', [
            'camera=()',
            'microphone=()',
            'geolocation=()',
            'payment=()',
            'usb=()',
            'interest-cohort=()',
        ].join(', '));

        // Cross-Origin policies
        newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
        newHeaders.set('Cross-Origin-Resource-Policy', 'same-origin');

        // Remove server fingerprinting headers
        newHeaders.delete('Server');
        newHeaders.delete('X-Powered-By');
        newHeaders.delete('X-AspNet-Version');

        return new Response(response.body, {
            status:     response.status,
            statusText: response.statusText,
            headers:    newHeaders,
        });
    }
};
