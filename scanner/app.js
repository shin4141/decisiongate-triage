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

  const money = /\$|usd|usdt|eth|sol|btc|円|¥|jpy|万円|ドル|payment|pay|invoice|fee|price|subscription/.test(t);
  const urgency = /urgent|asap|immediately|right now|today|within\s+\d+\s*(hours?|mins?)|期限|今日中|今すぐ|至急|残り\d+/.test(t);

  // split "permission" into login vs secret/credential
  const asks_login = /\b(login|sign\s?in)\b|ログイン/.test(t);
  const asks_secret =
    /\b(password|passcode|2fa|seed|seed\s?phrase|recovery\s?phrase|secret\s?key|private\s?key|wallet|signature|sign\s+transaction)\b|署名|シード|秘密鍵|権限/.test(t);

  const threat = /account will be closed|suspended|legal action|police|arrest|訴訟|凍結|停止|逮捕|違反/.test(t);
  const timeLimitPhrase = /limited time|only \d+ left|limited slots|last chance|先着|限定|最後の/.test(t);
  const attachment = /attached|attachment|pdf|docx|zip|exe|添付|ファイル/.test(t);
  const noContext = text.trim().length < 40;

  const hasUrl = ex.urls.length > 0;
  const hasMoney = money;
  const asksPermissionOrLogin = asks_secret || asks_login;
  const hasThreat = threat;
  const hasTimeLimitPhrase = timeLimitPhrase;
  const hasAttachment = attachment;

  // placeholders (later: maintain sender history / domain reputation)
  const domainUnknown = hasUrl; // v0: treat any domain as "unknown" until deepcheck exists
  const newSender = true;       // v0: assume new
  const highStakes = money || permission;

  const safeSurface = (!hasUrl && !hasMoney && !asksPermissionOrLogin && !hasThreat);

  return {
    has_money: hasMoney,
    has_urgency: urgency,
    asks_permission_or_login: asksPermissionOrLogin,
    has_url: hasUrl,
    domain_unknown: domainUnknown,
    has_shortener: ex.has_shortener,
    has_threat: hasThreat,
    impersonation_claim: false, // v0 stub
    has_time_limit_phrase: hasTimeLimitPhrase,
    new_sender: newSender,
    high_stakes: highStakes,
    has_attachment: hasAttachment,
    no_context: noContext,
    no_links: !hasUrl,
    no_money: !hasMoney,
    no_permission: !asksPermissionOrLogin,
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
  const status = $("status");

  const rules = await loadRules();

  $("run").onclick = () => {
    const text = input.value || "";
    const card = buildCard(text, rules);
    out.textContent = pretty(card);
    share.textContent =
      `${card.share_report.short}\n\n` +
      `Search:\n` +
      (card.search.queries || []).map(q => `- ${q.label}: ${q.q}`).join("\n");
    status.textContent = `Done. severity=${card.gate.severity}`;
  };

  $("clear").onclick = () => {
    input.value = "";
    out.textContent = "{}";
    share.textContent = "";
    status.textContent = "";
  };

  status.textContent = "Ready (local-first).";
}

main().catch(err => {
  $("status").textContent = `Error: ${err.message}`;
});
