import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import TotpQr from "@/components/totp-qr";

describe("TotpQr", () => {
  it("renders an SVG for the given otpauth URI", () => {
    const { container } = render(
      <TotpQr value="otpauth://totp/Athena:test?secret=JBSWY3DPEHPK3PXP&issuer=Athena" />,
    );
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
    // qrcode.react draws path/rect nodes for each module.
    expect(svg!.querySelectorAll("path,rect").length).toBeGreaterThan(0);
  });

  it("encodes different URIs into different module layouts", () => {
    const a = render(
      <TotpQr value="otpauth://totp/Alpha:one?secret=JBSWY3DPEHPK3PXP&issuer=Alpha" />,
    );
    const b = render(
      <TotpQr value="otpauth://totp/Bravo:two?secret=AAAAAAAAAAAAAAAA&issuer=Bravo" />,
    );
    expect(a.container.querySelector("svg")?.innerHTML).not.toBe(
      b.container.querySelector("svg")?.innerHTML,
    );
  });

  it("respects an explicit size prop", () => {
    const { container } = render(
      <TotpQr value="otpauth://totp/A:x?secret=AAAAAAAA" size={200} />,
    );
    const svg = container.querySelector("svg");
    // qrcode.react renders the matrix with width/height attrs reflecting `size`.
    expect(svg?.getAttribute("width")).toBe("200");
    expect(svg?.getAttribute("height")).toBe("200");
  });
});
