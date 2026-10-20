/**
 * AgentKit reports every wallet initialization and action invocation —
 * including the wallet address — to Coinbase's analytics endpoint, with no
 * switch to turn it off, and an HTTP error there surfaces as an unhandled
 * rejection that kills the process. Answer those requests locally instead.
 *
 * Import this module before anything from @coinbase/agentkit.
 */
const ANALYTICS_HOST = "cca-lite.coinbase.com";
const realFetch = globalThis.fetch;

globalThis.fetch = (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (new URL(url).host === ANALYTICS_HOST) {
    return Promise.resolve(new Response(null, { status: 204 }));
  }
  return realFetch(input, init);
};

export {};
