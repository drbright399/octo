import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { OnboardingGuide } from "@/components/onboarding-guide";
import type { Onboarding } from "@/contracts/integration";

const ONB: Onboarding = {
  summary: "Connect Datto in two parts.",
  webhook_url: "https://octo.example/api/v1/webhooks/datto",
  steps: [
    {
      title: "Add the webhook",
      body: "Paste the URL into Datto.",
      copy_value: "https://octo.example/api/v1/webhooks/datto",
    },
    {
      title: "Alert-raised payload",
      body: "Use this template.",
      code_sample: '{"event":"alert_raised"}',
    },
  ],
};

beforeEach(() => {
  // Reduce motion → instant step swap, so navigation is deterministic (no timers).
  window.matchMedia = vi
    .fn()
    .mockReturnValue({ matches: true }) as unknown as typeof window.matchMedia;
  Object.assign(navigator, {
    clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

describe("OnboardingGuide", () => {
  it("renders summary, first step, and the prominent webhook URL", () => {
    render(<OnboardingGuide onboarding={ONB} deliveryMode="hybrid" />);
    expect(screen.getByText("Connect Datto in two parts.")).toBeInTheDocument();
    expect(screen.getByText("Add the webhook")).toBeInTheDocument();
    expect(screen.getByText(/paste this into the vendor/i)).toBeInTheDocument();
    expect(screen.getByText("step 1 of 2")).toBeInTheDocument();
  });

  it("steps to the next panel", () => {
    render(<OnboardingGuide onboarding={ONB} deliveryMode="hybrid" />);
    expect(screen.queryByText("Alert-raised payload")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("next →"));
    expect(screen.getByText("Alert-raised payload")).toBeInTheDocument();
    expect(screen.getByText("step 2 of 2")).toBeInTheDocument();
  });

  it("copies the webhook URL to the clipboard", () => {
    render(<OnboardingGuide onboarding={ONB} deliveryMode="hybrid" />);
    fireEvent.click(screen.getAllByRole("button", { name: /copy/i })[0]);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(ONB.webhook_url);
  });

  it("omits the prominent webhook field for poll adapters but still shows steps", () => {
    render(
      <OnboardingGuide onboarding={{ ...ONB, webhook_url: null }} deliveryMode="poll" />,
    );
    expect(screen.queryByText(/paste this into the vendor/i)).not.toBeInTheDocument();
    expect(screen.getByText("Add the webhook")).toBeInTheDocument();
  });
});
