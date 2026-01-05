interface Env {
  ASSETS: Fetcher;
  R2: R2Bucket;
}

// Matches: orb-macos, orb-linux, orb-windows, orb-macos-0.1.0, orb-linux-1.2.3, etc.
const BINARY_PATTERN = /^orb-(macos|linux|windows)(-\d+\.\d+\.\d+)?$/;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(req.url);

    if (pathname.startsWith('/downloads/')) {
      const binary = pathname.replace('/downloads/', '');

      if (!binary || !BINARY_PATTERN.test(binary)) {
        return this.notFound(env);
      }

      // Download from `downloads/{binary}`
      const object = await env.R2.get(pathname.slice(1));

      if (object === null) {
        return this.notFound(env);
      }

      return new Response(object.body, {
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${binary}"`,
        },
      });
    }

    return this.notFound(env);
  },

  notFound(env: Env): Promise<Response> {
    return env.ASSETS.fetch('https://assets.local/404.html');
  }
}
