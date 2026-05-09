export const EMPTY_TEXT = '-';

const toFiniteNumber = (value?: number | null) => {
  if (value === null || value === undefined) return undefined;
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
};

export function formatBytes(value?: number | null, fractionDigits = 1) {
  const bytes = toFiniteNumber(value);
  if (bytes === undefined) return EMPTY_TEXT;
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const sign = bytes < 0 ? '-' : '';
  let size = Math.abs(bytes);
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  const digits = unitIndex === 0 ? 0 : fractionDigits;
  return `${sign}${size.toFixed(digits)} ${units[unitIndex]}`;
}

export function formatBytesPerSec(value?: number | null, fractionDigits = 1) {
  const formatted = formatBytes(value, fractionDigits);
  return formatted === EMPTY_TEXT ? EMPTY_TEXT : `${formatted}/s`;
}

export function formatPercent(value?: number | null, fractionDigits = 2) {
  const ratio = toFiniteNumber(value);
  if (ratio === undefined) return EMPTY_TEXT;
  return `${(ratio * 100).toFixed(fractionDigits)}%`;
}

export function formatNumber(value?: number | null, fractionDigits = 1) {
  const num = toFiniteNumber(value);
  if (num === undefined) return EMPTY_TEXT;
  return num.toFixed(fractionDigits);
}

export function formatDuration(value?: number | null) {
  const milliseconds = toFiniteNumber(value);
  if (milliseconds === undefined) return EMPTY_TEXT;

  let seconds = Math.max(0, Math.floor(milliseconds / 1000));
  const days = Math.floor(seconds / 86400);
  seconds %= 86400;
  const hours = Math.floor(seconds / 3600);
  seconds %= 3600;
  const minutes = Math.floor(seconds / 60);
  seconds %= 60;

  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  if (seconds || parts.length === 0) parts.push(`${seconds}s`);

  return parts.join(' ');
}

export function formatDateTime(value?: string | number | null) {
  if (value === null || value === undefined || value === '') return EMPTY_TEXT;
  const date = typeof value === 'number' ? new Date(value) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}
