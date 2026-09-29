import { once } from 'node:events';
import http from 'node:http';
import { afterAll, onTestFinished } from 'vitest';

/*
 * With a bare Express app, `supertest(app)` listens on `::` (all interfaces)
 * but connects to `127.0.0.1`.  On macOS another local process bound to
 * `127.0.0.1` on the same ephemeral port can answer instead of the app,
 * giving intermittent foreign responses (an unexpected 401, or
 * `Parse Error: Expected HTTP/, RTSP/ or ICE/`).
 *
 * `listen(app)` starts the app on `127.0.0.1:0`, waits for 'listening' and
 * returns the server, so supertest connects to exactly that socket:
 *
 *   const res = await request(await listen(app)).get('/path');
 *
 * The server is closed when the current test finishes, or after the file
 * when `listen` is called outside a test (e.g. in `beforeAll`).
 */

const openServers = new Set<http.Server>();

async function closeServer(server: http.Server): Promise<void> {
  if (!openServers.delete(server)) return;
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

export async function listen(app: http.RequestListener): Promise<http.Server> {
  const server = http.createServer(app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  openServers.add(server);
  try {
    onTestFinished(() => closeServer(server));
  } catch {
    // Not inside a test: closed by the afterAll below.
  }
  return server;
}

afterAll(async () => {
  await Promise.all([...openServers].map(closeServer));
});
