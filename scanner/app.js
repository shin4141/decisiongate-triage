const $ = (id) => document.getElementById(id);

const SEVERITY_ORDER = ["PASS", "DELAY", "BLOCK"];
const maxSeverity = (a, b) => SEVERITY_ORDER.indexOf(a) > SEVERITY_ORDER.indexOf(b) ? a : b;

function nowId() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `msg_${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

// --- extraction (minimal, local) ---
function extract(text) {
  const urls = [...text.matchAll(/\bhttps?:\/\/[^\s)]+/gi)].map(m => m[0]);
  const emails = [...text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)].map(m => m[0]);
  const phones = [...text.matchAll(/\+?\d[\d\s().-]{7,}\d/g)].map(m => m[0]);

  const domains = urls.map(u => {
    try { return new URL(u).hostname.toLowerCase(); } catch { return ""; }
  }).filter(Boolean);

  const hasShortener = domains.some(d => ["bit.ly","t.co","tinyurl.com","goo.gl","is.gd","ow.ly"].includes(d));

  return {
    urls: urls.map(u => {
      let domain = "";
      try { domain = new URL(u).hostname.toLowerCase(); } catch {}
      return { url: u, domain, is_shortener: ["bit.ly","t.co","tinyurl.com","goo.gl","is.gd","ow.ly"].includes(domain) };
    }),
    emails,
    phones,
    domains,
    has_shortener: hasShortener
  };
}

// --- signals (very rough v0) ---
function signals(text, ex) {
  const t = text.toLowerCase();

  // money / urgency
  const moneyRe =
    /\$|usd|usdt|eth|sol|btc|円|¥|jpy|万円|ドル|payment|pay|invoice|fee|price|subscription|subscribed|billing|charge|refund|transfer|send money|送金|支払い|請求|返金/;
  const urgencyRe =
    /urgent|asap|immediately|right now|today|within\s+\d+\s*(hours?|hrs?|mins?|minutes?)|期限|本日|至急|今すぐ|24時間|48時間|最終/;

  const hasMoney = moneyRe.test(t);
  const hasUrgency = urgencyRe.test(t);

  // login vs secret/credential
  const asksLogin = /\b(login|log in|sign\s?in)\b|ログイン/.test(t);

  const secretSeedKeyRe =
    /\b(password|passcode|2fa|otp|seed|seed\s?phrase|recovery\s?phrase|mnemonic|secret\s?key|private\s?key)\b|パスワード|シード|秘密鍵|復元フレーズ/;
  const asksSecretSeedKey = secretSeedKeyRe.test(t);

  // OTP/2FA code sharing request (phishing)
  const otpShareRe =
    /(\b(reply|send|share|tell)\b|返信|送って|送信して|教えて|共有して).{0,40}(\b(otp|2fa|verification\s?code|security\s?code|auth(entication)?\s?code|one[-\s]?time\s?code)\b|認証コード|確認コード|セキュリティコード|ワンタイムコード|ワンタイムパス)|(\b(otp|2fa|verification\s?code|security\s?code|auth(entication)?\s?code|one[-\s]?time\s?code)\b|認証コード|確認コード|セキュリティコード|ワンタイムコード|ワンタイムパス).{0,40}(\b(reply|send|share|tell)\b|返信|送って|送信して|教えて|共有して)/;
  const asksOtpShare = otpShareRe.test(t);
  /*
    Manual tests (OTP share):
    1) "Reply with the verification code you just received." => BLOCK
    2) "このSMSの認証コードを返信して" => BLOCK
    3) "Enter the code on the official site/app to continue." => PASS
  */

  // signature / approval (crypto-style)
  const sigApproveRe =
    /\b(sign|signature|approve|approval|authorize|confirm|verify wallet|connect wallet)\b|署名|承認|接続|ウォレット/;
  const asksSignatureOrApproval = sigApproveRe.test(t);

  // payment/transfer direct ask (separate from "money words")
  const payTransferRe =
    /\b(pay|payment|send|transfer|wire|remit|deposit|withdraw)\b|支払|送金|振込|入金|出金/;
  const asksPaymentOrTransfer = payTransferRe.test(t);

  // threats / time limit
  const threatRe =
    /account will be closed|suspended|legal action|police|arrest|訴訟|凍結|停止|逮捕|法的措置|閉鎖/;
  const hasThreat = threatRe.test(t);

  const timeLimitPhraseRe =
    /limited time|only \d+ left|limited slots|last chance|先着|限定|最後の|残りわずか/;
  const hasTimeLimitPhrase = timeLimitPhraseRe.test(t);

  // attachments: distinguish "exec/macro" vs normal
  const attachmentRe = /attached|attachment|添付|ファイル|pdf|docx|zip|rar|7z|dmg|exe|apk|scr|js|vbs|bat|cmd|ps1|xlsm|docm/i;
  const hasAttachment = attachmentRe.test(text);

  const execMacroRe = /\.(exe|dmg|apk|scr|js|vbs|bat|cmd|ps1|xlsm|docm)\b/i;
  const hasExecutableOrMacroAttachment = execMacroRe.test(text) || /\bmacro\b/i.test(text);

  // impersonation claim (support/security/admin)
  const impersonationRe =
    /\b(support|security|admin|moderator|official|team|compliance|trust & safety|customer service)\b|公式|運営|サポート|管理者|セキュリティ/;
  const hasImpersonationClaim = impersonationRe.test(t);

  // surface
  const hasUrl = ex.urls.length > 0;

  // domain allowlist to reduce false positives
  const TRUSTED_DOMAINS = new Set([
    "github.com",
    "google.com",
    "reddit.com",
    "x.com",
    "twitter.com",
    "apple.com",
    "microsoft.com",
    "discord.com",
    "telegram.org",
    "wikipedia.org",
    "paypal.com",
    "stripe.com"
  ]);
  const isTrustedDomain = (domain) => {
    if (!domain) return false;
    if (TRUSTED_DOMAINS.has(domain)) return true;
    for (const root of TRUSTED_DOMAINS) {
      if (domain.endsWith(`.${root}`)) return true;
    }
    return false;
  };
  const extractedDomains = (ex.domains && ex.domains.length > 0)
    ? ex.domains
    : ex.urls.map(u => (u && u.domain ? u.domain : "")).filter(Boolean);
  const domainUnknown = extractedDomains.some(d => !isTrustedDomain(d));
  /*
    Manual tests:
    1) "See https://github.com/openai/ and https://x.com/xyz" => domain_unknown: false
    2) "Please review https://login.example.com/reset now" => domain_unknown: true
    3) "Docs at https://docs.google.com and https://support.apple.com" => domain_unknown: false
  */
  const newSender = true;       // until history exists

  // high stakes: login or payment or secret or signature
  const highStakes = asksLogin || asksPaymentOrTransfer || asksSecretSeedKey || asksSignatureOrApproval;

  const noContext = text.trim().length < 40;
  const safeSurface = (!hasUrl && !hasMoney && !asksLogin && !asksSecretSeedKey && !hasThreat);

  return {
    // used by rules.json
    has_money: hasMoney,
    has_urgency: hasUrgency,

    asks_login: asksLogin,

    asks_secret_or_seed_or_private_key_or_mnemonic: asksSecretSeedKey,
    asks_otp_share: asksOtpShare,
    asks_signature_or_approval: asksSignatureOrApproval,
    asks_payment_or_transfer: asksPaymentOrTransfer,
    has_executable_or_macro_attachment: hasExecutableOrMacroAttachment,

    has_url: hasUrl,
    domain_unknown: domainUnknown,
    has_shortener: ex.has_shortener,

    has_threat: hasThreat,
    has_time_limit_phrase: hasTimeLimitPhrase,

    new_sender: newSender,
    high_stakes: highStakes,

    // existing / compatibility
    has_attachment: hasAttachment,
    no_context: noContext,

    has_impersonation_claim: hasImpersonationClaim,

    // safe_pattern helpers (v0.2-general expects these names)
    no_links: !hasUrl,
    no_money: !hasMoney,
    no_secret_request: !asksSecretSeedKey && !asksOtpShare && !asksSignatureOrApproval && !asksPaymentOrTransfer,
    no_threat: !hasThreat
  };
}

function matchRule(rule, sig) {
  return (rule.if || []).every(k => Boolean(sig[k]));
}

function buildCard(text, rulesJson) {
  const ex = extract(text);
  const sig = signals(text, ex);

  let severity = "PASS";
  const reasons = [];
  const evidence = new Set();

  for (const r of rulesJson.rules || []) {
    if (matchRule(r, sig)) {
      severity = maxSeverity(severity, r.severity);
      reasons.push(`rule:${r.id}`);
      (r.evidence || []).forEach(e => evidence.add(e));
    }
  }

  // minimal summary v0
  const summary_1l =
    severity === "BLOCK" ? "High-risk pattern detected. Do not act yet." :
    severity === "DELAY" ? "Needs verification. Pause and check evidence." :
    "Low-risk surface. Still verify if stakes rise.";

  const shareShort =
    `Gate=${severity}. Reasons: ${reasons.slice(0,4).join(", ") || "none"}. ` +
    `URLs=${ex.urls.length}, Emails=${ex.emails.length}, Phones=${ex.phones.length}.`;

  const card = {
    id: nowId(),
    summary_1l,
    intent: "",
    asks: [],
    risk_factors: Object.entries(sig).filter(([k,v]) => v && k.startsWith("has_") || v && k.includes("asks_")).map(([k])=>k),
    extracted: {
      urls: ex.urls,
      emails: ex.emails,
      phones: ex.phones,
      handles: [],
      dates: [],
      money: []
    },
    gate: {
      severity,
      until_iso: null,
      reasons,
      evidence: [...evidence]
    },
    search: {
      queries: (ex.domains[0] ? [
        { label: "X search", q: `"${ex.domains[0]}" scam` },
        { label: "Google", q: `${ex.domains[0]} phishing report` },
        { label: "Reddit", q: `${ex.domains[0]} scam site:reddit.com` }
      ] : [
        { label: "Google", q: `message template scam keywords` }
      ])
    },
    share_report: {
      short: shareShort,
      family_one_liner: `Gate=${severity}. Pause. Verify via search links before any payment/login/approval.`
    },
    deepcheck: { status: "not_run", sources: [], evidence_add: [] }
  };

  return card;
}

async function loadRules() {
  const res = await fetch("./rules.json", { cache: "no-store" });
  if (!res.ok) throw new Error("rules.json not found");
  return await res.json();
}

function pretty(obj) { return JSON.stringify(obj, null, 2); }

async function main() {
  const input = $("input");
  const out = $("out");
  const share = $("share");
  const gate = $("gate");
  const reasons = $("reasons");
  const counts = $("counts");
  const status = $("status");

  const rules = await loadRules();

  $("run").onclick = () => {
    const text = input.value || "";
    const card = buildCard(text, rules);
    out.textContent = pretty(card);
    gate.textContent = card.gate.severity;
    gate.classList.remove("pass", "delay", "block");
    const sev = String(card.gate.severity || "").toLowerCase();
    if (sev) gate.classList.add(sev);
    reasons.textContent = (card.gate.reasons || []).join(", ") || "none";
    counts.textContent = `URLs=${card.extracted.urls.length}, Emails=${card.extracted.emails.length}, Phones=${card.extracted.phones.length}`;
    const enc = encodeURIComponent;
const mk = (label, q) => {
  const url =
    label.includes("Google") ? `https://www.google.com/search?q=${enc(q)}` :
    label.includes("Reddit") ? `https://www.google.com/search?q=${enc(q)}` :
    label.includes("X") ? `https://x.com/search?q=${enc(q)}` :
    `https://www.google.com/search?q=${enc(q)}`;
  return `- <a href="${url}" target="_blank" rel="noopener noreferrer">${label}</a>: ${q}`;
};

share.innerHTML =
  `${card.share_report.short}<br><br>` +
  `Search:<br>` +
  (card.search.queries || []).map(q => mk(q.label, q.q)).join("<br>");

      `${card.share_report.short}\n\n` +
      `Search:\n` +
      (card.search.queries || []).map(q => `- ${q.label}: ${q.q}`).join("\n");
    status.textContent = `Done. severity=${card.gate.severity}`;
  };

  $("clear").onclick = () => {
    input.value = "";
    out.textContent = "{}";
    share.textContent = "";
    gate.textContent = "—";
    gate.classList.remove("pass", "delay", "block");
    reasons.textContent = "—";
    counts.textContent = "—";
    status.textContent = "";
  };

  status.textContent = "Ready (local-first).";
}

main().catch(err => {
  $("status").textContent = `Error: ${err.message}`;
});
