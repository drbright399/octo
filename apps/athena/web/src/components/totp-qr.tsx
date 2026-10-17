/**
 * TotpQr — renders an otpauth:// URI as a scannable QR matrix.
 *
 * Wraps `qrcode.react`'s `QRCodeSVG` so we control sizing, border, and
 * caption from one place. Used in:
 *   - /login/setup (first-login wizard, stage 2)
 *   - Settings → Account → Reset TOTP modal
 *
 * Security note: TOTP enrollment is gated by the backend `/totp/enroll/begin`
 * endpoint — the `value` we render here is just a presentation of the
 * server-issued URI. If the operator scans a QR that doesn't match the
 * URI's actual contents they'll fail the 6-digit verify step on the next
 * stage, so visual misrender is detectable but annoying. Error-correction
 * level is set to "M" (15% recovery) — the URI fits comfortably and "M" is
 * what the major authenticator apps recommend.
 */
import { type FC } from "react";
import { QRCodeSVG } from "qrcode.react";

interface TotpQrProps {
  readonly value: string;
  readonly size?: number;
}

const TotpQr: FC<TotpQrProps> = ({ value, size = 168 }) => (
  <div className="flex flex-col items-center">
    <div className="rounded-sm border border-border bg-white p-2">
      <QRCodeSVG
        value={value}
        size={size}
        level="M"
        bgColor="#ffffff"
        fgColor="#0a0414"
        marginSize={0}
      />
    </div>
    <span className="mt-2 font-mono text-[10px] uppercase tracking-wider text-text-dim">
      ·· scan with authenticator app ··
    </span>
  </div>
);

export default TotpQr;
