export class AuthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly data?: Record<string, unknown>;
  /**
   * `true` when the HTTP status was passed explicitly to the constructor
   * (either `new AuthError(msg, 409)` or `new AuthError(msg, 'CODE', 409)`),
   * `false` when `statusCode` is the default `401`.
   *
   * Used to map errors thrown from hooks (e.g. `onBeforeDeleteUser`): an
   * `AuthError` without an explicit status answers 500, not 401.
   */
  public readonly hasExplicitStatus: boolean;

  constructor(
    message: string,
    codeOrStatus: string | number = 'AUTH_ERROR',
    statusCodeOrCode?: number | string,
    data?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AuthError';
    if (typeof codeOrStatus === 'number') {
      this.statusCode = codeOrStatus;
      this.code = typeof statusCodeOrCode === 'string' ? statusCodeOrCode : 'AUTH_ERROR';
      this.hasExplicitStatus = true;
    } else {
      this.code = codeOrStatus;
      this.statusCode = typeof statusCodeOrCode === 'number' ? statusCodeOrCode : 401;
      this.hasExplicitStatus = typeof statusCodeOrCode === 'number';
    }
    this.data = data;
  }
}
