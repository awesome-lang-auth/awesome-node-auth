export class AuthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly data?: Record<string, unknown>;

  constructor(
    message: string,
    codeOrStatus: string | number = 'AUTH_ERROR',
    statusCodeOrCode: number | string = 401,
    data?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AuthError';
    if (typeof codeOrStatus === 'number') {
      this.statusCode = codeOrStatus;
      this.code = typeof statusCodeOrCode === 'string' ? statusCodeOrCode : 'AUTH_ERROR';
    } else {
      this.code = codeOrStatus;
      this.statusCode = typeof statusCodeOrCode === 'number' ? statusCodeOrCode : 401;
    }
    this.data = data;
  }
}
