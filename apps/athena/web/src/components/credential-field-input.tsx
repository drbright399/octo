import type { FC } from "react";
import type { CredentialField } from "@/contracts/integration";

interface Props {
  readonly field: CredentialField;
  readonly value: string;
  readonly onChange: (v: string) => void;
}

export const CredentialFieldInput: FC<Props> = ({ field, value, onChange }) => {
  const id = `field-${field.name}`;
  const isSecret = field.kind === "password";
  const inputType = isSecret ? "password" : field.kind === "url" ? "url" : "text";
  const baseClass =
    "w-full rounded border border-border bg-bg-input px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none";

  return (
    <label htmlFor={id} className="mb-3 block">
      <span className="mb-1 flex items-center gap-2 text-xs text-text-secondary">
        {field.label}
        {field.required ? <span className="text-critical">*</span> : null}
        {isSecret ? (
          <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
            secret
          </span>
        ) : null}
        {/* Who mints a webhook secret: the vendor's can only be pasted in. */}
        {field.secret_origin === "vendor" ? (
          <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
            issued by the vendor — paste it
          </span>
        ) : null}
      </span>
      {field.kind === "enum" && field.choices ? (
        <select
          id={id}
          required={field.required}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={baseClass}
        >
          <option value="">— select —</option>
          {field.choices.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      ) : field.kind === "webhook-url-out" ? (
        // Display-only value (e.g. the inbound webhook URL) — not a credential input.
        <input
          id={id}
          type="text"
          readOnly
          value={value || field.placeholder || ""}
          className={`${baseClass} cursor-default text-text-secondary`}
        />
      ) : (
        <input
          id={id}
          type={inputType}
          required={field.required}
          autoComplete={isSecret ? "new-password" : "off"}
          spellCheck={false}
          placeholder={field.placeholder}
          {...(field.pattern ? { pattern: field.pattern } : {})}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={baseClass}
        />
      )}
      {field.description ? (
        <span className="mt-1 block text-[11px] text-text-dim">{field.description}</span>
      ) : null}
    </label>
  );
};
