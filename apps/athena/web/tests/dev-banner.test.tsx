import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// vitest runs with MODE="test" by default — explicitly stub the cases
// the component switches on.

describe("DevBanner", () => {
  it("renders the synthetic-data warning when MODE === 'development'", async () => {
    vi.stubEnv("MODE", "development");
    // Dynamic import AFTER env stub so the component sees the patched value.
    const { default: DevBanner } = await import("@/components/dev-banner");
    render(<DevBanner />);
    expect(screen.getByText(/synthetic data only/i)).toBeInTheDocument();
    vi.unstubAllEnvs();
  });

  it("renders nothing in production builds (MODE !== 'development')", async () => {
    vi.stubEnv("MODE", "production");
    vi.resetModules();  // Force re-evaluation under the new env
    const { default: DevBanner } = await import("@/components/dev-banner");
    const { container } = render(<DevBanner />);
    expect(container).toBeEmptyDOMElement();
    vi.unstubAllEnvs();
  });
});
