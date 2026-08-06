// Minimal `next/server` stand-in so API route handlers can be exercised under
// `node --test` without booting Next. Only NextResponse.json is used by the routes
// under test, and it is backed by the platform Response.
class NextResponse extends Response {
  static json(body, init = {}) {
    return new Response(JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { "content-type": "application/json", ...(init.headers ?? {}) },
    });
  }
}

module.exports = { NextResponse };
