// SPA mode (SPEC §9): no SSR, no prerendering. Everything runs in the browser
// so that secrets never touch a server-rendering process.
export const ssr = false;
export const prerender = false;
