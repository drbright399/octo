/**
 * Relative time formatting. Pure, deterministic given `now`. Tests inject
 * `now` to avoid clock dependence.
 */
export function formatRelative(isoTimestamp: string, now: Date = new Date()): string {
  const then = new Date(isoTimestamp);
  if (Number.isNaN(then.getTime())) {
    return "unknown";
  }

  const seconds = Math.floor((now.getTime() - then.getTime()) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;

  const years = Math.floor(days / 365);
  return `${years}y ago`;
}
