//
//  TwoFactorFlow.swift
//  SideSign
//
//  2FA 流程中的纯决策逻辑：不发起网络请求，便于单元测试。
//

import Foundation

enum TwoFactorFlow {
    /// 根据发码渠道生成验证提示。语音码必须继续按语音提示与验证，
    /// 否则 Apple 会因渠道不一致拒绝验证码。
    static func verificationRequest(
        mode: TwoFactorDeliveryMode,
        phoneNumbers: [TrustedPhoneNumber],
        activeID: String,
        error: String?
    ) -> TwoFactorRequest {
        if mode == .voice {
            return .voice(phoneNumbers: phoneNumbers, activeID: activeID, error: error)
        }
        return .sms(phoneNumbers: phoneNumbers, activeID: activeID, error: error)
    }

    /// GSA 返回这些状态时应退避重试，而不是切换身份或清空 adi.pb。
    static func isRetryable(status: Int) -> Bool {
        status == 429 || status == 433 || status == 503
    }

    /// 退避重试仍被 503/433 拒绝时，才用 SideInstaller 的 Mac 身份做最后一次尝试。
    /// 429 是限流，换身份无益且可能加重风控，因此不在此列。
    static func shouldRetryAsMac(status: Int) -> Bool {
        status == 503 || status == 433
    }

    /// SideInstaller `remote_v3::get_client_info`：公开 anisette 服务器仍可能返回
    /// com.apple.dt.Xcode 客户端，GSA 会以 503 拒绝；回退时统一报 Mac15,7。
    static let fallbackClientInfo = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    static let fallbackUserAgent = "akd/1.0 CFNetwork/808.1.4"

    /// 只替换身份头，保留调用方的 method/body/Content-Type/Accept。
    /// 重建请求会丢掉 JSON 媒体类型，正是 2FA 验证失败的原因之一。
    static func applyingFallbackIdentity(to request: URLRequest) -> URLRequest {
        var copy = request
        copy.setValue(fallbackClientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
        copy.setValue(fallbackUserAgent, forHTTPHeaderField: "User-Agent")
        return copy
    }

    /// Apple 是否明确拒绝电话/语音投递（含 iCloud 连接类文案）。
    static func isPhoneRefusal(status: Int, title: String?, message: String?) -> Bool {
        let combined = [title, message]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ": ")
            .lowercased()
        return status == 401 || status == 403 || status == 423
            || combined.contains("icloud")
            || combined.contains("could not connect")
            || combined.contains("forbidden")
    }

    /// 把服务器返回的 phone id 映射为 Apple 需要的数字 id。
    /// 非数字时按已知号码列表的索引（1-based）映射，映射不到则明确报错。
    static func numericPhoneID(_ raw: String, known: [TrustedPhoneNumber]) throws -> Int {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let parsed = Int(trimmed) {
            return parsed
        }
        if let index = known.firstIndex(where: {
            $0.id.trimmingCharacters(in: .whitespacesAndNewlines) == trimmed
        }) {
            return index + 1
        }
        throw DeveloperPortalError.invalidParameters(cause: "Unsupported phone id: \(raw)")
    }

    /// 一次登录最多允许两轮 2FA（首轮 + 重登后 Apple 再要求一次）。
    static func canStartRound(_ completedRounds: Int) -> Bool {
        completedRounds < 2
    }
}
