export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error('Invalid API path');
  }
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body) headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch('/api/v1' + path, {
      ...options, headers, credentials: 'same-origin', cache: 'no-store',
      redirect: 'error',
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new ApiError(0, 'Cannot connect to IntelSOC. Check the private gateway.');
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const message = typeof data?.detail === 'string'
      ? data.detail : 'Request failed (HTTP ' + response.status + ')';
    throw new ApiError(response.status, message);
  }
  if (data === null) throw new ApiError(response.status, 'Unexpected server response');
  return data as T;
}

export function post<T>(path: string, body: unknown): Promise<T> {
  return api<T>(path, {method: 'POST', body: JSON.stringify(body)});
}
