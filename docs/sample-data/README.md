# Sample data for Design-first work

Synthetic data shapes used by Design Claude for visual prototyping
without needing the full backend.

Each file matches the typed shape its consumer expects:

- `alerts.json` — array of `AlertRow` (see
  `apps/athena/web/src/contracts/alert.ts`)
- `buoys.json` — array of `RotatableSource` (see
  `apps/athena/widgets/components/default-attention-rotator.tsx`)
- `integrations.json` — `{ definitions, instances }` (see
  `apps/athena/web/src/contracts/integration.ts`)

## Conventions

- **Synthetic only.** No real customer names. Use the fictional fleet's
  slugs: `acme`, `globex`, `initech`, `umbrella`, `hooli`.
- **Realistic but obvious.** Use plausible MSP-customer shapes so
  visuals feel real, but make sure no synthetic name could be
  mistaken for an actual organization.
- **Match the typed shape.** If you add a field, also add it to the
  TS contract in `apps/athena/web/src/contracts/`.
- **Keep it small.** 3–10 rows per file. Visual designers don't need
  large datasets; if you need to test rendering at scale, generate in
  the Vitest test instead.
