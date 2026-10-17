# Athena Console — web (v3)

Vite + React + TS + Tailwind frontend for the framework-aligned Athena
Console. Talks to OCTO over `/api/v1/*` (session-cookie auth).

This **fully owns** the operator UI surface in V3:

- `/login` — password + TOTP sign-in (+ forgot-password sub-flow)
- `/login/reset?token=` — consume password-reset email link
- `/login/magic?token=` — consume magic-link sign-in
- `/login/setup` — forced first-login wizard (initial password →
  TOTP enrollment → save backup codes)
- `/dashboard` — operator landing
- `/tickets`, `/fleet` — placeholders pending bridge wiring
- `/settings/account` — profile + auth + active-sessions self-service
- `/settings/operators` — admin operator management
- `/settings/integrations` — adapter catalog + configured instances

A legacy console server (V2) previously served the login pages on top
of V3's React build. V3 now owns its own login surface; V2 can retire to
a plain static host once V3 is verified in production.

## Layout

```
apps/athena/
├── framework/          # Python: layouts, widget registry client, boot
├── widgets/
│   ├── system/         # Python: system widget registrations
│   ├── role_defaults/  # Python: per-role default layouts
│   └── components/     # TSX: render components (consumed by web/)
└── web/                # this directory — Vite + React + TS app
    ├── src/
    │   ├── App.tsx              # shell: topbar + sidebar + route switch
    │   ├── main.tsx             # React entry
    │   ├── components/          # topbar, sidebar, network-bg, catalog-popout, etc.
    │   ├── contracts/           # TS mirror of shared_*_contract + operator + integration
    │   ├── lib/
    │   │   ├── api.ts           # All HTTP wrappers (auth, account, admin, adapters)
    │   │   ├── router.ts        # Path-based router (useRoute / useSearchParam)
    │   │   ├── theme.ts         # Dark/light/system theme hook
    │   │   ├── time.ts
    │   │   └── widget-layout.ts
    │   ├── pages/
    │   │   ├── dashboard.tsx
    │   │   ├── login.tsx
    │   │   ├── login-reset.tsx
    │   │   ├── login-magic.tsx
    │   │   ├── login-setup.tsx
    │   │   ├── placeholder.tsx
    │   │   ├── settings.tsx     # parent w/ tab nav
    │   │   └── settings/
    │   │       ├── account.tsx
    │   │       ├── operators.tsx
    │   │       └── integrations.tsx
    │   └── mock/                # only used for storybook-style tests
    └── tests/                   # Vitest + Testing Library
```

The render components in `apps/athena/widgets/components/` are imported
via the `@widgets/*` path alias. They are dumb: given typed rows + props,
they render. No fetching, auth, or mutation — that all lives upstream.

## Commands

```bash
cd apps/athena/web
npm install
npm run dev          # http://localhost:5173 — Vite proxies /api → :8001
npm run typecheck
npm run lint
npm test
npm run build
```

For the **full local-dev pair** (backend + frontend in one terminal),
run `./scripts/dev.sh` from the repo root instead — see
`apps/octo/README.md` for the dev workflow.

## Routing model

V3 uses **path-based routing** via the in-house `lib/router.ts`:

```ts
const [route, navigate] = useRoute();      // route is window.location.pathname
const token = useSearchParam("token");      // re-renders on navigation
matches(route, "/settings")                 // prefix match helper
```

Path-based (not hash-based) because email-flow links (`/login/reset?token=…`,
`/login/magic?token=…`) must match a route literally. The Vite dev server
+ any production static host both need SPA fallback (any path →
`index.html`) — Vite has this on by default; production hosts must be
configured for it.

## Auth posture

- **No tokens in `localStorage`**. Session lives in an `httpOnly` cookie
  set by OCTO (`athena_session`). The Vite client never sees the token.
- **`getMe()` returning null → hard redirect to `/login`**. App.tsx
  enforces this on every navigation so a session-expired user can't
  silently stay on a stale dashboard with empty widgets.
- **Setup gate**: when `/auth/me` reports `needs_setup=true`, App.tsx
  hard-redirects to `/login/setup`. The backend `setup_gate` middleware
  enforces the same rule server-side — the SPA redirect is the UX
  half.
- **Sensitive operations** (email change, backup-codes regen, admin-
  driven password reset) require `current_password` proof on the
  request body. Self-password change bypasses the proof when
  `must_change_password=1` (initial-setup path).

## Security posture

- No tokens in `localStorage`. Bridge auth lives in `httpOnly` cookies
  set by the auth-core (parity with G.1 Console v2). The Vite client
  never sees the token.
- Server enforces, UI presents. Components never trust their inputs to
  be authoritative.
- All user/source content rendered as text nodes — never `innerHTML`,
  never `dangerouslySetInnerHTML`. Tested against `<script>`/`<img>`
  injection in `tests/default-alert-feed.test.tsx`.
- `referrer-policy: no-referrer` + `X-Content-Type-Options: nosniff`
  declared at the document level; production CSP is set by the
  deployment's reverse proxy.
- No `eval`, no `Function()`, no dynamic `import()` of untrusted strings.

## Account tab affordances

The Account page (`/settings/account`) is fully data-driven from
`/api/v1/auth/me` + sibling endpoints. Three panels:

1. **Profile** — username (read-only), inline-editable display name,
   email (modal with current-password proof), role badge, tenant scope.
2. **Authentication** — Change password, Reset/Enroll TOTP, Generate
   new backup codes. Each opens a modal demanding `current_password`
   for sensitive rotations.
3. **Active sessions** — live list of currently-active sessions for the
   operator (revoked/expired filtered out at the backend). Per-row
   Revoke + footer Sign-out-everywhere-else.

Athena renders the operator by `display_name` when set, falling back
to `username` (dropdown initial + label, dashboard greeting, account
header).

## Operators tab affordances

The Operators page (`/settings/operators`, admin-tier gated) provides
end-to-end operator administration:

- Create operator (magic-link returned for handoff)
- Disable / Enable
- Reset password (admin sets a temp password directly, target forced
  to rotate on next sign-in)
- Grant role (filtered by caller tier — admin sees admin/analyst/viewer,
  super_admin sees all four)
- Revoke role (× chip on the role badge, when caller can manage target
  and role isn't the operator's only role)
- **Tenant scope picker** per row — checkbox menu with "* all tenants"
  + every active client in the bundle. Special warning when granting
  `*` to a viewer (viewers are end-customers, almost always single-
  tenant).

## Integrations tab affordances

- Configured instances render as cards on load (live from
  `/api/v1/integrations`).
- "**+ Add integration**" opens a right-side slide-out catalog:
  category rail (SIEM / RMM / Managed SOC / Network / All) + search
  filter + adapter grid. Click an adapter → switches to the
  credential wizard inside the same panel.
- "Test connection" hits the smoke-test endpoint with the candidate
  credentials.
- "Save & encrypt" persists via the instance-create endpoint, which
  encrypts to the bundle's adapter-credentials vault, registers the
  instance, and starts the poller.

## Contract sync with Python

`src/contracts/widget.ts`, `src/contracts/alert.ts`,
`src/contracts/operator.ts`, `src/contracts/integration.ts` are
hand-mirrored from the Python contract definitions. Drift is an open
risk; the planned mitigation is a snapshot test that the bridge wiring
step will add (importing both contracts and asserting equality in CI).

## Tests

39 vitest tests as of 2026-05-12:

- `default-alert-feed.test.tsx` — alert-row render + XSS hardening
- `default-attention-rotator.test.tsx` — rotation animation gating
- `catalog-popout.test.tsx` — category rail + filter + step transition
- `login.test.tsx` — password+TOTP flow, forgot-password, reset, magic-link

Run from repo root:

```bash
cd apps/athena/web && npx vitest run
```
