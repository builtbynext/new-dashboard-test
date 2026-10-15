/**
 * HTTP Basic Auth gate for the whole site.
 *
 * Credentials are NOT hardcoded here (this repo is public) — they come from
 * Vercel environment variables, set in the project's Settings > Environment
 * Variables:
 *   DASHBOARD_USER
 *   DASHBOARD_PASS
 *
 * Until both are set in the Vercel project, every request is rejected.
 */

export const config = {
  matcher: "/:path*",
};

function unauthorized() {
  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Outlet performance dashboard"',
    },
  });
}

export default function middleware(request) {
  const expectedUser = process.env.DASHBOARD_USER;
  const expectedPass = process.env.DASHBOARD_PASS;

  if (!expectedUser || !expectedPass) {
    // Fail closed: if the env vars aren't configured yet, don't serve the
    // page unprotected.
    return unauthorized();
  }

  const authHeader = request.headers.get("authorization") || "";
  const [scheme, encoded] = authHeader.split(" ");

  if (scheme === "Basic" && encoded) {
    let decoded = "";
    try {
      decoded = atob(encoded);
    } catch (e) {
      return unauthorized();
    }
    const sepIndex = decoded.indexOf(":");
    const user = decoded.slice(0, sepIndex);
    const pass = decoded.slice(sepIndex + 1);

    if (user === expectedUser && pass === expectedPass) {
      return; // let the request through
    }
  }

  return unauthorized();
}
