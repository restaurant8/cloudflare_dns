export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function apiFetch<T>(path: string, token?: string | null, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let message = response.statusText;
    try {
      const payload = await response.json();
      message = payload.detail || payload.message || message;
    } catch {
      // keep status text
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

const appTimeZone = "Asia/Shanghai";
const dateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  timeZone: appTimeZone,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false
});
const timeFormatter = new Intl.DateTimeFormat("zh-CN", {
  timeZone: appTimeZone,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false
});

function parseApiDate(value: string): Date | null {
  const trimmed = value.trim();
  const normalized = /([zZ]|[+-]\d{2}:?\d{2})$/.test(trimmed) ? trimmed : `${trimmed.replace(" ", "T")}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function fmtDate(value: string | null): string {
  if (!value) return "-";
  const date = parseApiDate(value);
  return date ? dateTimeFormatter.format(date) : value;
}

export function fmtTime(value: string | null): string {
  if (!value) return "-";
  const date = parseApiDate(value);
  return date ? timeFormatter.format(date) : value;
}
