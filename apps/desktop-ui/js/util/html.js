/**
 * html.js - the single place where untrusted values are made safe for
 * innerHTML template strings.
 *
 * Almost everything this UI renders comes from somewhere an attacker can
 * influence: process names and command lines from the inspected host, file
 * names, EVTX/PCAP-derived strings, DNS names, chat messages, CTF challenge
 * text. Every such value interpolated into an HTML template MUST go through
 * escapeHtml (element text) or escapeAttr (a double-quoted attribute value).
 * When building markup by hand is not needed at all, prefer textContent.
 *
 * Pure string implementation on purpose: the previous per-module copies used
 * `div.textContent = s; return div.innerHTML`, which does not escape quotes
 * and therefore let a value break out of an attribute (data-*, title, value).
 */

const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;'
};

const HTML_ESCAPE_RE = /[&<>"'`]/g;

/**
 * Escape a value for use as HTML text content. null/undefined become ''.
 * @param {unknown} value
 * @returns {string}
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(HTML_ESCAPE_RE, (ch) => HTML_ESCAPES[ch]);
}

/**
 * Escape a value for use inside a double-quoted attribute value, e.g.
 * `data-id="${escapeAttr(id)}"`. Always quote the attribute. Never use this
 * to build an event-handler attribute or a URL (href/src) from data: bind
 * handlers with addEventListener instead.
 * @param {unknown} value
 * @returns {string}
 */
export function escapeAttr(value) {
  return escapeHtml(value);
}
