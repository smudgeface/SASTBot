/**
 * Copy text to the clipboard with a fallback for non-secure-context pages.
 *
 * `navigator.clipboard.writeText` is only available in **secure contexts**
 * (HTTPS or `localhost`). When the app is served from a LAN IP over plain
 * HTTP — which is how the homelab is currently reached, e.g.
 * `http://<LAN-IP>:5173/` — `navigator.clipboard` is `undefined` and a
 * direct call throws a TypeError that the click handler silently swallows.
 *
 * The fallback creates an off-screen `<textarea>`, selects its contents, and
 * runs `document.execCommand('copy')`. That API is officially deprecated but
 * remains the only thing that works in insecure contexts on every browser
 * we care about.
 *
 * Returns `true` on success, `false` on failure. Caller is expected to toast
 * the result either way so the user gets feedback.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  // Preferred path — secure context only.
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to the legacy textarea fallback. Some browsers throw
      // even in secure contexts when document.hasFocus() is false (rare,
      // but happens on iframe-embedded use).
    }
  }

  // Legacy fallback. Position off-screen, no focus shift, no scroll jump.
  if (typeof document === "undefined") return false;
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "-9999px";
  ta.style.left = "-9999px";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}
