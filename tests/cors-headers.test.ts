/**
 * The auth router's CORS layer allows the X-Auth-Strategy request header, so a
 * browser app on another listed origin can use bearer mode (the preflight of
 * every call carrying `X-Auth-Strategy: bearer` must allow it).
 */
import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const origin = 'https://app.example.com';

async function buildApp(): Promise<express.Application> {
  const userStore = new InMemoryUserStore();
  await userStore.create({ email: 'user@example.com', password: await new PasswordService().hash('pw') });
  const app = express();
  app.use(express.json());
  app.use('/auth', createAuthRouter(userStore, {
    accessTokenSecret: 'cors-access-secret-very-long-and-secure',
    refreshTokenSecret: 'cors-refresh-secret-very-long-and-secure',
  }, { cors: { origins: [origin] } }));
  return app;
}

describe('auth router CORS', () => {
  it('the preflight allows X-Auth-Strategy', async () => {
    const app = await buildApp();
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', origin)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type,x-auth-strategy');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe(origin);
    expect(res.headers['access-control-allow-headers']).toBe('Content-Type,Authorization,X-CSRF-Token,X-Api-Key,X-Auth-Strategy');
  });

  it('a cross-origin bearer login gets the CORS headers and the tokens in the body', async () => {
    const app = await buildApp();
    const res = await request(app)
      .post('/auth/login')
      .set('Origin', origin)
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'user@example.com', password: 'pw' });
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe(origin);
    expect(res.headers['access-control-allow-headers']).toContain('X-Auth-Strategy');
    expect(res.body.accessToken).toBeTruthy();
  });

  it('an unlisted origin still gets no CORS headers', async () => {
    const app = await buildApp();
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', 'https://evil.example.com')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'x-auth-strategy');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(res.headers['access-control-allow-headers']).toBeUndefined();
  });
});
