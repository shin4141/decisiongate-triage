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
  const actionVerbRe = /\b(reply|send|share|tell|forward|give)\b/i;
  const codeNounRe = /\b(verification code|security code|auth(?:entication)? code|one[-\s]?time (?:code|password)|6[-\s]?digit code|code you received|otp|2fa)\b/i;
  const actionThenCodeRe = new RegExp(`${actionVerbRe.source}[\\s\\S]{0,80}${codeNounRe.source}`, "i");
  const codeThenActionRe = new RegExp(`${codeNounRe.source}[\\s\\S]{0,80}${actionVerbRe.source}`, "i");
  const hasActionVerb = actionVerbRe.test(t);
  const hasEnterOfficial = /\b(enter|type|input)\b.*\b(official|app|site)\b/i.test(t);
  let asksOtpShare = actionThenCodeRe.test(t) || codeThenActionRe.test(t);
  if (hasEnterOfficial && !hasActionVerb) asksOtpShare = false;
  /*
    Acceptance tests:
    1) "Reply with the verification code you received." => BLOCK
    2) "Support: reply with the 6-digit code." => BLOCK
    3) "Do not share this code. Enter it on the official app/site." => PASS (no URL)
  */

  // KYC/ID/selfie sharing request (phishing)
  const kycShareVerbRe = /\b(reply|send|share|tell|forward|give|attach)\b|返信して|送って|送信して|教えて|共有して|添付して/i;
  const kycUploadVerbRe = /\bupload\b|アップロード/;
  const kycNounRe =
    /\b(id|identity|passport|driver'?s license|license|selfie|address|insurance)\b|マイナンバー|身分証|免許証|パスポート|セルフィー|顔写真|住所|保険証/i;
  const kycActionThenNounRe = new RegExp(`${kycShareVerbRe.source}[\\s\\S]{0,80}${kycNounRe.source}`, "i");
  const kycNounThenActionRe = new RegExp(`${kycNounRe.source}[\\s\\S]{0,80}${kycShareVerbRe.source}`, "i");
  const kycHasShareVerb = kycShareVerbRe.test(t);
  const kycUploadOfficial = kycUploadVerbRe.test(t) && /\b(official|app|site)\b/i.test(t);
  let asksKycShare = kycActionThenNounRe.test(t) || kycNounThenActionRe.test(t);
  if (kycUploadOfficial && !kycHasShareVerb) asksKycShare = false;
  /*
    Manual tests (KYC share):
    A) "本人確認のため、身分証とセルフィーをこのDMに送ってください。" => BLOCK
    B) "Please send your ID and a selfie to verify your account." => BLOCK
    C) "Upload your ID on the official website to complete verification." => PASS (or DELAY only if URL present)
  */
  /*
    Manual tests (OTP share):
    A) "Support team here. Reply with the 6-digit verification code you just received." => BLOCK
    B) "This code is for you. Do not share it. Enter it on the official app/site." => PASS (or DELAY only if URL present)
    C) "Send me your 2FA code to verify your account." => BLOCK
  */

  // signature / approval (crypto-style)
  const sigApproveRe =
    /\b(sign|signature|approve|approval|authorize|confirm|verify wallet|connect wallet)\b|署名|承認|接続|ウォレット/;
  const asksSignatureOrApproval = sigApproveRe.test(t);

  // payment/transfer direct ask (separate from "money words")
  const payTransferRe =
    /\b(pay|payment|send|transfer|wire|remit|deposit|withdraw)\b|支払|送金|振込|振り込|振り込み|入金|出金/;
  const asksPaymentOrTransfer = payTransferRe.test(t);

  // gift card request
  const giftActionRe =
    /\b(buy|purchase|get|send|provide)\b|買って|購入|送って|教えて/i;
  const giftNounRe =
    /(gift\s?card|giftcard|itunes\s?card|apple\s?gift\s?card|google\s?play\s?card|amazon\s?gift\s?card|steam\s?card|ギフトカード|ギフト券|プリペイド|電子マネー|itunesカード|apple\s?gift\s?card|google\s?playカード|amazonギフト|appleカード|steamカード)/i;
  const giftCodeRe = /\b(gift\s?card\s?(code|pin)|code|pin)\b|コード|番号|pin/i;
  const giftActionThenNounRe = new RegExp(`${giftActionRe.source}[\\s\\S]{0,60}${giftNounRe.source}`, "i");
  const giftNounThenActionRe = new RegExp(`${giftNounRe.source}[\\s\\S]{0,60}${giftActionRe.source}`, "i");
  const giftNounThenCodeRe = new RegExp(`${giftNounRe.source}[\\s\\S]{0,40}${giftCodeRe.source}`, "i");
  const giftCodeThenNounRe = new RegExp(`${giftCodeRe.source}[\\s\\S]{0,40}${giftNounRe.source}`, "i");
  const asksGiftCard =
    giftActionThenNounRe.test(t) ||
    giftNounThenActionRe.test(t) ||
    giftNounThenCodeRe.test(t) ||
    giftCodeThenNounRe.test(t);
  /*
    Manual tests (gift card):
    A) "iTunesカード買って番号送って" => BLOCK
    B) "Please buy an Amazon gift card and send me the code." => BLOCK
    C) "ギフトカードの話題（雑談）だよ" => PASS
  */

  // delivery / flea-market spoof
  const deliveryMarketRe =
    /(ヤマト|佐川|日本郵便|ゆうパック|不在|再配達|配達|荷物|追跡|伝票|お届け|住所確認|関税|メルカリ|ラクマ|PayPayフリマ|購入|発送|受取|取引|delivery|parcel|shipment|reschedule|failed delivery|customs|tracking|waybill)/i;
  const hasDeliveryOrMarketSpoof = deliveryMarketRe.test(t);
  /*
    Manual tests (delivery/market spoof):
    A) "不在のため再配達が必要です。こちらから確認：https://example.com" => DELAY (or BLOCK only if high_stakes words appear)
    B) "配送先の確認のためログインしてください：https://example.com/login" => BLOCK
    C) "メルカリ取引：受取確認はこちら https://example.com" => DELAY (unless high_stakes)
  */

  // payment / refund / billing scam
  const paymentRefundRe =
    /(返金|返金手続き|請求|未払い|支払い確認|料金|利用料金|引き落とし|決済|異常な支払い|二重請求|PayPay|PayPal|Stripe|クレジット|カード|銀行|振込|口座|refund|billing|invoice|overdue|payment required|subscription|chargeback|double charge|bank transfer|credit card|paypal|stripe)/i;
  const hasPaymentRefundScam = paymentRefundRe.test(t);
  /*
    Manual tests (payment/refund):
    A) "返金手続きのためこちらを確認：https://example.com" => DELAY (unless high_stakes)
    B) "未払い料金があります。ログインして支払い：https://example.com/login" => BLOCK
    C) "PayPal refund required. Please login: https://example.com" => BLOCK
  */

  // prize / grant / giveaway scam
  const prizeGrantRe =
    /(当選|受賞|賞金|ギフト券|給付金|支援金|補助金|還元|受け取り|受取|prize|winner|lottery|giveaway|grant|subsidy|reward|gift card|claim your reward)/i;
  const hasPrizeOrGrantScam = prizeGrantRe.test(t);
  const feeTermsRe =
    /(手数料|税金|送料|振込|入金|fee|tax|shipping|transfer|deposit)/i;
  const hasMoneyOrFeeTerms = feeTermsRe.test(t);
  /*
    Manual tests (prize/grant):
    A) "当選しました。受取はこちら：https://example.com" => DELAY
    B) "当選金の受取に手数料が必要です。今すぐ支払ってください。" => BLOCK
    C) "You've won a prize. Login to claim: https://example.com/login" => BLOCK
  */

  // family emergency / impersonation scam
  const familyRe =
    /(母|父|娘|息子|家族|叔父|叔母|親|兄|姉|弟|妹|hi mom|hi mum|mom|dad)/i;
  const emergencyRe =
    /(緊急|助けて|今すぐ|事故|病院|弁護士|警察|携帯壊れた|新しい番号|この番号に連絡|line追加|番号変わった|emergency|help me|accident|hospital|lawyer|police|new number|phone broken)/i;
  const hasFamilyEmergencyScam =
    (/\bhi (mom|mum)\b/i.test(t)) || (familyRe.test(t) && emergencyRe.test(t));
  /*
    Manual tests (family emergency):
    A) "母さん、携帯壊れた。新しい番号だよ。" => DELAY
    B) "今すぐ振り込んで。事故で入院してる。" => BLOCK
    C) "Hi mum, my phone is broken. Save my new number." => DELAY
  */

  // police / legal threat scam
  const policeLegalRe =
    /(警察|刑事|捜査|逮捕|容疑|口座凍結|差し押さえ|訴訟|裁判所|支払命令|未納|督促|罰金|police|detective|arrest|warrant|lawsuit|court|subpoena|legal action|frozen account|seizure|penalty|fine)/i;
  const hasPoliceLegalThreat = policeLegalRe.test(t);
  /*
    Manual tests (police/legal):
    A) "警察です。あなたの口座が凍結されます。至急連絡してください。" => DELAY or BLOCK (prefer BLOCK if has_threat triggers)
    B) "裁判所からの通知。ログインして確認：https://example.com/login" => BLOCK
    C) "Police notice: pay a fine now or face arrest. https://example.com" => BLOCK
  */

  // investment / side-hustle scam
  const investmentHustleRe =
    /(投資|副業|不労所得|高利回り|確実に儲かる|元本保証|月利|日利|利益保証|先出し|自動売買|AI投資|シグナル配信|コピトレ|紹介|招待|限定枠|line追加|オープンチャット|こっちのリンク|コミュニティ参加|investment|passive income|guaranteed returns|risk[-\s]?free|high yield|daily profit|copy trading|signals|ai trading|exclusive group|invite)/i;
  const hasInvestmentHustleScam = investmentHustleRe.test(t);
  /*
    Manual tests (investment/hustle):
    A) "限定の投資コミュニティはこちら：https://example.com" => DELAY
    B) "元本保証・高利回り。ログインして参加：https://example.com/login" => BLOCK
    C) "AI trading group. Send a deposit now." => BLOCK
  */

  // guaranteed profit marketing claim (delay-only)
  const guaranteedProfitRe =
    /(絶対儲かる|確実に儲かる|元本保証|損しない|必ず勝てる|100%|guaranteed returns|risk[-\s]?free|no loss|100%\s*profit|sure win)/i;
  const hasGuaranteedProfitClaim = guaranteedProfitRe.test(t);
  /*
    Manual tests (guaranteed profit):
    A) "絶対儲かる投資です！" => DELAY
    B) "Guaranteed returns. Join our group." => DELAY
  */

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
    asks_kyc_share: asksKycShare,
    asks_signature_or_approval: asksSignatureOrApproval,
    asks_payment_or_transfer: asksPaymentOrTransfer,
    has_executable_or_macro_attachment: hasExecutableOrMacroAttachment,

    has_url: hasUrl,
    domain_unknown: domainUnknown,
    has_shortener: ex.has_shortener,
    asks_gift_card: asksGiftCard,
    has_delivery_or_market_spoof: hasDeliveryOrMarketSpoof,
    has_payment_refund_scam: hasPaymentRefundScam,
    has_prize_or_grant_scam: hasPrizeOrGrantScam,
    has_money_or_fee_terms: hasMoneyOrFeeTerms,
    has_family_emergency_scam: hasFamilyEmergencyScam,
    has_police_legal_threat: hasPoliceLegalThreat,
    has_investment_hustle_scam: hasInvestmentHustleScam,
    has_guaranteed_profit_claim: hasGuaranteedProfitClaim,

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
    no_threat: !hasThreat,
    no_guaranteed_profit_claim: !hasGuaranteedProfitClaim
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
    debug_signals: sig,
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
  const copyQuick = $("copy-quick");
  const copyReport = $("copy-report");
  const quickShareText = $("quick-share-text");
  const status = $("status");

  let lastCard = null;
  const copyText = async (text) => {
    if (!text) {
      status.textContent = "Copy failed";
      return;
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        prompt("Copy:", text);
      }
      status.textContent = "Copied";
    } catch {
      prompt("Copy:", text);
      status.textContent = "Copy failed";
    }
  };

  copyQuick.onclick = () => {
    if (!lastCard) {
      status.textContent = "Run analysis first";
      return;
    }
    copyText(lastCard.share_report.family_one_liner || "");
  };
  copyReport.onclick = () => {
    if (!lastCard) {
      status.textContent = "Run analysis first";
      return;
    }
    const reportText =
      `${lastCard.share_report.short}\n\n` +
      `Search:\n` +
      (lastCard.search.queries || []).map(q => `- ${q.label}: ${q.q}`).join("\n");
    copyText(reportText);
  };

  $("run").onclick = async () => {
    const text = input.value || "";
    const rulesNow = await loadRules();
    const card = buildCard(text, rulesNow);
    lastCard = card;
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
    quickShareText.textContent = card.share_report.family_one_liner || "—";
    status.textContent = `Done. severity=${card.gate.severity}`;
  };

  $("clear").onclick = () => {
    input.value = "";
    out.textContent = "{}";
    share.textContent = "";
    lastCard = null;
    quickShareText.textContent = "—";
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
