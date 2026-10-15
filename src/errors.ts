/** Error whose message is safe to show to the model (caused by the tool input). */
export class ToolInputError extends Error {
  readonly code = "invalid_input";
}

/** Upstream (Wazuh API / Indexer) failure. Details stay in internal logs only. */
export class UpstreamError extends Error {
  constructor(
    readonly code:
      "upstream_auth" | "upstream_forbidden" | "upstream_not_found" | "upstream_timeout" | "upstream_error",
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export class NotFoundError extends Error {
  readonly code = "not_found";
}
