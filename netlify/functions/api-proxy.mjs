// Same-origin proxy from Netlify to the Python API hosted separately.
// Set API_ORIGIN in the Netlify site environment (for example, your Render URL).
export const config = { path: "/api/*" };

const blockedHeaders = new Set([
  "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
]);

export default async (request) => {
  const origin = (process.env.API_ORIGIN || "").replace(/\/+$/, "");
  if (!origin) return Response.json({ error: "API_ORIGIN is not configured for this Netlify site." }, { status: 503 });

  let base;
  try { base = new URL(origin); }
  catch { return Response.json({ error: "API_ORIGIN must be a valid HTTPS URL." }, { status: 500 }); }
  if (base.protocol !== "https:" && base.hostname !== "localhost" && base.hostname !== "127.0.0.1") {
    return Response.json({ error: "API_ORIGIN must use HTTPS." }, { status: 500 });
  }

  const incoming = new URL(request.url);
  const target = `${origin}${incoming.pathname}${incoming.search}`;
  const headers = new Headers();
  for (const [key, value] of request.headers) {
    if (!blockedHeaders.has(key.toLowerCase())) headers.set(key, value);
  }
  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "manual",
      duplex: "half",
    });
    const responseHeaders = new Headers();
    for (const [key, value] of upstream.headers) {
      if (!blockedHeaders.has(key.toLowerCase())) responseHeaders.append(key, value);
    }
    responseHeaders.set("cache-control", "no-store");
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return Response.json({ error: "The PaySovereignAI API could not be reached." }, { status: 502 });
  }
};
