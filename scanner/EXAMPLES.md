# DecisionGate Message Triage — Regression Examples

Use these as quick regression checks. Each example lists input, expected gate, and a short note when useful.

## OTP Share Request (BLOCK)

**Expected Gate:** BLOCK
```
Reply with the verification code you received.
```
Note: Reply + verification code.

**Expected Gate:** BLOCK
```
Support team here. Please send me your 2FA code.
```

**Expected Gate:** BLOCK
```
このSMSの認証コードを返信して。
```

## KYC / ID / Selfie Sharing Request (BLOCK)

**Expected Gate:** BLOCK
```
本人確認のため、身分証とセルフィーをこのDMに送ってください。
```

**Expected Gate:** BLOCK
```
Please send your ID and a selfie to verify your account.
```

**Expected Gate:** BLOCK
```
パスポートの写真を送ってください。
```

## Delivery / Market Spoof Link (DELAY or BLOCK)

**Expected Gate:** DELAY
```
不在のため再配達が必要です。こちらから確認：https://example.com
```
Note: Delivery + URL.

**Expected Gate:** BLOCK
```
配送先の確認のためログインしてください：https://example.com/login
```
Note: Delivery + URL + login.

**Expected Gate:** DELAY
```
メルカリ取引：受取確認はこちら https://example.com
```

## Payment / Refund / Billing Scam (DELAY or BLOCK)

**Expected Gate:** DELAY
```
返金手続きのためこちらを確認：https://example.com
```

**Expected Gate:** BLOCK
```
未払い料金があります。ログインして支払い：https://example.com/login
```

**Expected Gate:** BLOCK
```
PayPal refund required. Please login: https://example.com
```

## Prize / Grant Scams (DELAY or BLOCK)

**Expected Gate:** DELAY
```
当選しました。受取はこちら：https://example.com
```

**Expected Gate:** BLOCK
```
当選金の受取に手数料が必要です。今すぐ支払ってください。
```
Note: Prize + fee request.

**Expected Gate:** BLOCK
```
You won a prize. Login to claim: https://example.com/login
```

## Family Emergency (DELAY or BLOCK)

**Expected Gate:** DELAY
```
母さん、携帯壊れた。新しい番号だよ。
```

**Expected Gate:** BLOCK
```
今すぐ振り込んで。事故で入院してる。
```

**Expected Gate:** DELAY
```
Hi mum, my phone is broken. Save my new number.
```

## Police / Legal Impersonation (BLOCK)

**Expected Gate:** BLOCK
```
裁判所からの通知。ログインして確認：https://example.com/login
```

**Expected Gate:** BLOCK
```
Police notice: pay a fine now or face arrest. https://example.com
```

**Expected Gate:** BLOCK
```
警察です。未納の罰金があるので支払ってください：https://example.com
```

## Investment / Side-Hustle (DELAY or BLOCK)

**Expected Gate:** DELAY
```
限定の投資コミュニティはこちら：https://example.com
```

**Expected Gate:** BLOCK
```
元本保証・高利回り。ログインして参加：https://example.com/login
```

**Expected Gate:** BLOCK
```
AI trading group. Send a deposit now.
```

## Guaranteed Profit Claims (DELAY-only)

**Expected Gate:** DELAY
```
絶対儲かる投資です。今がチャンス。
```

**Expected Gate:** DELAY
```
元本保証で確実に増やせます。損しません。
```

**Expected Gate:** DELAY
```
Guaranteed returns. Risk-free. No loss.
```

## Gift Card Request (BLOCK)

**Expected Gate:** BLOCK
```
iTunesカード買って番号送って
```

**Expected Gate:** BLOCK
```
Please buy an Amazon gift card and send me the code.
```

**Expected Gate:** BLOCK
```
Amazonギフトカードのコードを教えて。
```
