import type { FC } from "react";

interface PlaceholderProps {
  readonly title: string;
  readonly note: string;
}

const PlaceholderPage: FC<PlaceholderProps> = ({ title, note }) => (
  <section className="rounded-lg border border-border bg-bg-surface p-8 text-center">
    <h1 className="mb-2 text-lg font-semibold text-text-primary">{title}</h1>
    <p className="text-sm text-text-dim">{note}</p>
  </section>
);

export default PlaceholderPage;
