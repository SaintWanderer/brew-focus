export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (url.pathname === '/donors' && request.method === 'GET') {
      const data = await env.DONORS_KV.get('donors');
      const donors = data ? JSON.parse(data) : [];
      return new Response(JSON.stringify(donors), {
        headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
      });
    }

    if (url.pathname === '/submit-name' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch {
        return new Response('Invalid JSON', { status: 400, headers: corsHeaders() });
      }
      const { sessionId, name } = body;
      if (!sessionId) return new Response('Missing sessionId', { status: 400, headers: corsHeaders() });

      // Verify session with Stripe
      const stripeRes = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
        headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` }
      });
      if (!stripeRes.ok) return new Response('Invalid session', { status: 400, headers: corsHeaders() });
      const session = await stripeRes.json();
      if (session.payment_status !== 'paid') return new Response('Not paid', { status: 402, headers: corsHeaders() });

      const displayName = (name || '').trim().slice(0, 50) || 'Anonymous';
      if (displayName !== 'Anonymous' && !moderateName(displayName)) {
        return new Response(JSON.stringify({ error: 'Name contains disallowed content.' }), {
          status: 422, headers: { ...corsHeaders(), 'Content-Type': 'application/json' }
        });
      }
      const amount = session.amount_total ? (session.amount_total / 100).toFixed(2) : '0.00';
      const currency = session.currency?.toUpperCase() || 'USD';

      const existing = await env.DONORS_KV.get('donors');
      const donors = existing ? JSON.parse(existing) : [];

      const idx = donors.findIndex(d => d.sessionId === sessionId);
      if (idx >= 0) {
        donors[idx].name = displayName;
      } else {
        donors.unshift({ name: displayName, amount, currency, ts: Date.now(), sessionId });
        if (donors.length > 100) donors.length = 100;
      }
      await env.DONORS_KV.put('donors', JSON.stringify(donors));

      return new Response(JSON.stringify({ received: true }), {
        headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
      });
    }

    if (url.pathname === '/webhook' && request.method === 'POST') {
      const body = await request.text();
      const sig = request.headers.get('stripe-signature');

      let event;
      try {
        event = await verifyStripeWebhook(body, sig, env.STRIPE_WEBHOOK_SECRET);
      } catch (err) {
        return new Response(`Webhook error: ${err.message}`, { status: 400 });
      }

      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        if (session.payment_status === 'paid') {
          const amount = session.amount_total ? (session.amount_total / 100).toFixed(2) : '0.00';
          const currency = session.currency?.toUpperCase() || 'USD';

          const existing = await env.DONORS_KV.get('donors');
          const donors = existing ? JSON.parse(existing) : [];

          // Only add if not already present (submit-name may have already stored it)
          if (!donors.find(d => d.sessionId === session.id)) {
            donors.unshift({ name: 'Anonymous', amount, currency, ts: Date.now(), sessionId: session.id });
            if (donors.length > 100) donors.length = 100;
            await env.DONORS_KV.put('donors', JSON.stringify(donors));
          }
        }
      }

      return new Response(JSON.stringify({ received: true }), {
        headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not found', { status: 404, headers: corsHeaders() });
  },
};

function moderateName(name) {
  const n = name.toLowerCase().replace(/[^a-z0-9\s]/g, '');
  const banned = [
    'nigger','nigga','chink','spic','kike','wetback','gook','towelhead',
    'raghead','beaner','cracker','honky','zipperhead','coon','jigaboo',
    'porch monkey','sambo','spook','jungle bunny','sand nigger',
    'faggot','fag','dyke','tranny','retard','retarded',
    'nazi','heil','kkk','white power','white supremacy','1488',
    'fuck','shit','cunt','bitch','asshole','bastard','whore','slut',
    'kill','murder','rape','terrorist','jihad',
  ];
  for (const term of banned) {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`(^|\\s|\\d)${escaped}(\\s|\\d|$)`).test(n)) return false;
    // Also catch no-space variations for single-word slurs
    if (term.split(' ').length === 1 && n.includes(term)) return false;
  }
  return true;
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, stripe-signature',
  };
}

async function verifyStripeWebhook(payload, sigHeader, secret) {
  if (!sigHeader) throw new Error('Missing stripe-signature header');

  const pairs = Object.fromEntries(
    sigHeader.split(',').map(p => {
      const i = p.indexOf('=');
      return [p.slice(0, i), p.slice(i + 1)];
    })
  );
  const timestamp = pairs['t'];
  const signature = pairs['v1'];

  if (!timestamp || !signature) throw new Error('Invalid stripe-signature format');
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) {
    throw new Error('Webhook timestamp too old');
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const buf = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${timestamp}.${payload}`)
  );
  const computed = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  if (computed !== signature) throw new Error('Signature mismatch');

  return JSON.parse(payload);
}
