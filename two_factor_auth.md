# 两步验证（2FA）技术详解

## 一、什么是两步验证（2FA）

两步验证（Two-Factor Authentication，2FA）是一种身份认证机制，要求用户在登录时提供**两种不同类型**的凭证，才能完成身份验证。

单纯依赖密码存在被盗、撞库、钓鱼等风险。2FA 通过引入第二个独立因素，使得攻击者即便拿到密码也无法登录。

### 认证三要素

| 类型 | 说明 | 举例 |
|------|------|------|
| **你知道的**（Knowledge） | 只有你知道的信息 | 密码、PIN |
| **你拥有的**（Possession） | 你持有的设备或令牌 | 手机、硬件密钥、动态口令 App |
| **你是谁**（Inherence） | 生物特征 | 指纹、面容 ID |

> **2FA = 密码（第一步）+ 任意一种其他因素（第二步）**

### 典型登录流程

```
用户输入账号密码 → 第一步验证通过
         ↓
触发第二步验证（选择其中一种方式）：
  ├── 设备通行密钥（Passkey）→ 生物识别确认
  ├── 动态口令（TOTP）       → 输入 6 位数字
  └── 邮件验证码             → 输入邮件收到的 OTP
         ↓
全部通过 → 登录成功
```

---

## 二、设备通行密钥（Passkey）

### 是什么

Passkey（通行密钥）是基于 **FIDO2 / WebAuthn** 标准的无密码认证方案。它使用**非对称加密（公私钥对）**，私钥永久存储在设备的安全芯片（TEE / Secure Enclave）中，永远不离开设备，服务端只保存公钥。

### 注册流程

```
客户端                                    服务端
  │                                         │
  │──── 1. 请求注册 ────────────────────────>│
  │                                         │
  │<─── 2. 返回 challenge（随机数）+ 配置 ───│
  │                                         │
  │  3. 安全芯片生成公私钥对                 │
  │     私钥存入 Secure Enclave（不可导出）  │
  │     用户通过生物识别授权                 │
  │                                         │
  │──── 4. 发送公钥 + 设备信息 ────────────>│
  │                                         │
  │                          5. 保存公钥    │
```

### 认证流程

```
客户端                                    服务端
  │                                         │
  │──── 1. 请求登录 ────────────────────────>│
  │                                         │
  │<─── 2. 返回 challenge（随机数）──────────│
  │                                         │
  │  3. 用户通过生物识别（Face ID/指纹）     │
  │     安全芯片用私钥对 challenge 签名      │
  │                                         │
  │──── 4. 发送签名结果 ────────────────────>│
  │                                         │
  │              5. 用公钥验证签名 → 通过   │
```

### 核心特性

| 特性 | 说明 |
|------|------|
| **抗钓鱼** | 私钥绑定到特定域名（Relying Party ID），仿冒网站无法触发签名 |
| **抗泄露** | 服务端只存公钥，即使数据库泄露也无法冒充用户 |
| **抗暴力破解** | 没有密码可以猜测 |
| **跨设备同步** | 通过 iCloud Keychain（Apple）/ Google Password Manager 同步 |
| **标准规范** | W3C WebAuthn Level 2 + FIDO2 |

### 密钥存储位置

| 平台 | 存储位置 |
|------|----------|
| iOS / macOS | Secure Enclave + iCloud Keychain 同步 |
| Android | StrongBox / TEE + Google Password Manager |
| Windows | Windows Hello TPM 芯片 |
| 硬件密钥 | YubiKey 等 FIDO2 硬件设备 |

---

## 三、动态口令（TOTP）

### 是什么

TOTP（Time-based One-Time Password，基于时间的一次性密码），基于 **RFC 6238** 标准。Google Authenticator、Authy、Microsoft Authenticator 等 App 使用的都是这种方式。每隔 30 秒自动刷新一个 6 位数字，用完即废。

### 注册流程

```
服务端生成 Secret（随机密钥，Base32 编码）
         ↓
生成二维码（包含 otpauth://totp/... URI）
         ↓
用户用 Authenticator App 扫码
         ↓
Secret 存入 App，用户输入当前 OTP 验证绑定成功
```

### 口令生成算法

TOTP 本质是 HOTP（HMAC-based OTP）的时间变体：

```
T       = floor(当前Unix时间戳 / 30)   ← 每30秒一个时间窗口
msg     = T 的大端字节序（8字节）
hmac    = HMAC-SHA1(secret, msg)       ← 20字节
offset  = hmac[19] & 0x0f              ← 动态截断偏移
code    = (hmac[offset:offset+4] & 0x7fffffff) % 1_000_000
```

最终得到 6 位数字，有效期 30 秒（服务端通常允许前后 ±1 窗口的误差，即 90 秒容忍范围）。

### 验证流程

```
用户打开 App 看到 6 位数字
         ↓
输入到登录页面
         ↓
服务端用相同 Secret + 当前时间窗口计算预期值
         ↓
比对是否一致 → 通过
```

### QR Code URI 格式

```
otpauth://totp/{issuer}:{account}?secret={SECRET}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
```

### 核心特性

| 特性 | 说明 |
|------|------|
| **离线可用** | 不需要网络，仅依赖时钟 |
| **一次性** | 每个 OTP 只能用一次 |
| **时效短** | 30 秒自动失效 |
| **弱点** | 实时中间人攻击（MITM）可转发有效 OTP，不如 Passkey 安全 |
| **兼容性好** | 几乎所有 Authenticator App 都支持 |

---

## 四、邮件验证码

服务端生成随机 OTP（通常 6 位数字），通过邮件发送给用户，有效期一般 5~10 分钟，用完即失效。

**优点**：实现最简单，用户无需额外 App  
**缺点**：依赖邮件服务可靠性，安全性低于 TOTP 和 Passkey，邮箱被入侵则 2FA 形同虚设

---

## 五、三种方式对比

| 特性 | 设备通行密钥（Passkey） | 动态口令（TOTP） | 邮件验证码 |
|------|-------------------------|------------------|------------|
| 安全级别 | ★★★★★ | ★★★★ | ★★★ |
| 抗钓鱼攻击 | 是（域名绑定） | 否 | 否 |
| 抗实时中间人 | 是 | 否 | 否 |
| 需要网络 | 注册时需要 | 不需要 | 需要 |
| 用户体验 | 最好（生物识别） | 较好 | 一般 |
| 设备丢失风险 | 低（云端同步） | 中（需备份 Secret） | 无 |
| 实现复杂度 | 高 | 中 | 低 |
| 推荐场景 | 高安全场景 | 通用场景 | 低成本场景 |

---

## 六、Go 开源库

### 动态口令（TOTP / HOTP）

#### `github.com/pquerna/otp` — 推荐

功能最完整，同时支持 TOTP 和 HOTP，内置二维码生成。

```go
import (
    "github.com/pquerna/otp/totp"
    "image/png"
    "os"
)

// 注册：生成 Secret 和二维码
key, err := totp.Generate(totp.GenerateOpts{
    Issuer:      "MyApp",
    AccountName: "user@example.com",
})
secret := key.Secret() // 存入数据库，与用户绑定

// 将二维码保存为图片（或转 base64 返回给前端）
img, _ := key.Image(200, 200)
f, _ := os.Create("qrcode.png")
png.Encode(f, img)

// 验证用户输入的 OTP
valid := totp.Validate(userInputCode, secret)
```

#### `github.com/xlzd/gotp` — 轻量替代

```go
import "github.com/xlzd/gotp"

otp := gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO")
fmt.Println(otp.Now())                              // 获取当前 OTP
fmt.Println(otp.Verify("123456", time.Now().Unix())) // 验证
fmt.Println(otp.ProvisioningUri("user@example.com", "MyApp")) // 生成 URI
```

---

### 设备通行密钥（WebAuthn / Passkey）

#### `github.com/go-webauthn/webauthn` — 推荐

目前最活跃、最完整的 Go WebAuthn 实现。

```go
import "github.com/go-webauthn/webauthn/webauthn"

// 初始化
w, err := webauthn.New(&webauthn.Config{
    RPDisplayName: "MyApp",
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com"},
})

// ---- 注册 ----

// Step 1: 生成注册选项，返回给前端
options, sessionData, err := w.BeginRegistration(user)
// 将 sessionData 存入 session，将 options 序列化返回给前端

// Step 2: 接收前端提交的 credential，完成注册
credential, err := w.FinishRegistration(user, *sessionData, r)
// 将 credential 存入数据库，与用户绑定

// ---- 认证 ----

// Step 1: 生成认证选项，返回给前端
options, sessionData, err := w.BeginLogin(user)

// Step 2: 接收前端签名结果，完成验证
credential, err := w.FinishLogin(user, *sessionData, r)
```

前端配合使用 Web API：
```javascript
// 注册
const credential = await navigator.credentials.create({ publicKey: options });

// 认证
const assertion = await navigator.credentials.get({ publicKey: options });
```

---

### 二维码生成

#### `github.com/skip2/go-qrcode`

```go
import "github.com/skip2/go-qrcode"

// 保存为文件
qrcode.WriteFile(key.URL(), qrcode.Medium, 256, "qrcode.png")

// 生成 []byte，转 base64 返回给前端
png, _ := qrcode.Encode(key.URL(), qrcode.Medium, 256)
base64Img := base64.StdEncoding.EncodeToString(png)
// 前端用 <img src="data:image/png;base64,{base64Img}"> 显示
```

---

### 库汇总

| 库 | 用途 | 备注 |
|----|------|------|
| `github.com/pquerna/otp` | TOTP / HOTP | 功能全，内置二维码，首选 |
| `github.com/xlzd/gotp` | TOTP / HOTP | 轻量，API 简洁 |
| `github.com/go-webauthn/webauthn` | Passkey / FIDO2 / WebAuthn | 最活跃的 Go WebAuthn 库 |
| `github.com/skip2/go-qrcode` | 二维码生成 | 生成 TOTP 绑定二维码 |

---

## 七、实现建议

根据图示场景（设备通行密钥 + 动态口令 + 邮件验证码），推荐技术选型：

```
设备通行密钥  →  go-webauthn/webauthn
动态口令      →  pquerna/otp
邮件验证码    →  crypto/rand 生成 OTP + 邮件 SDK 发送
二维码        →  pquerna/otp 内置 / skip2/go-qrcode
```

安全细节注意事项：
- TOTP Secret 存入数据库前应**加密存储**（AES-GCM 等）
- WebAuthn credential 中的 `SignCount` 应每次验证后更新，防止克隆攻击
- 邮件 OTP 需限制发送频率（如每分钟最多 1 次）和尝试次数（如最多 5 次）
- 建议同时支持**备用恢复码**（Recovery Codes），防止用户丢失设备后无法登录
