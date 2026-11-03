//
//  TwoFactorFlowTests.swift
//  SideSignTests
//
//  2FA 纯决策逻辑的回归测试：语音渠道、错误分类、phone id 映射、2FA 轮次上限。
//

import Foundation
import Testing
@testable import SideSign

@Suite("2FA Flow Policy Tests")
struct TwoFactorFlowTests {

    private let phones = [
        TrustedPhoneNumber(id: "1", number: "+1 555 0100"),
        TrustedPhoneNumber(id: "2", number: "+1 555 0101"),
    ]

    @Test("Voice codes keep the voice channel")
    func voiceVerificationRequest() {
        let request = TwoFactorFlow.verificationRequest(
            mode: .voice,
            phoneNumbers: phones,
            activeID: "2",
            error: "wrong code"
        )
        #expect(request == .voice(phoneNumbers: phones, activeID: "2", error: "wrong code"))
    }

    @Test("SMS and trusted-device modes map to the SMS prompt")
    func smsVerificationRequest() {
        for mode in [TwoFactorDeliveryMode.sms, .trustedDevice] {
            let request = TwoFactorFlow.verificationRequest(
                mode: mode,
                phoneNumbers: phones,
                activeID: "1",
                error: nil
            )
            #expect(request == .sms(phoneNumbers: phones, activeID: "1", error: nil))
        }
    }

    @Test("Only 429/433/503 are retryable")
    func retryableStatuses() {
        #expect(TwoFactorFlow.isRetryable(status: 429))
        #expect(TwoFactorFlow.isRetryable(status: 433))
        #expect(TwoFactorFlow.isRetryable(status: 503))
        #expect(!TwoFactorFlow.isRetryable(status: 403))
        #expect(!TwoFactorFlow.isRetryable(status: 500))
    }

    @Test("Phone refusal only for refusal statuses and iCloud wording")
    func phoneRefusalClassification() {
        #expect(TwoFactorFlow.isPhoneRefusal(status: 403, title: nil, message: nil))
        #expect(TwoFactorFlow.isPhoneRefusal(status: 423, title: nil, message: nil))
        #expect(TwoFactorFlow.isPhoneRefusal(
            status: 500,
            title: "Could not connect to iCloud",
            message: nil
        ))
        #expect(!TwoFactorFlow.isPhoneRefusal(
            status: 500,
            title: "Internal Server Error",
            message: "try again later"
        ))
    }

    @Test("Numeric phone ids pass through")
    func numericPhoneID() throws {
        #expect(try TwoFactorFlow.numericPhoneID("2", known: phones) == 2)
        #expect(try TwoFactorFlow.numericPhoneID(" 7 ", known: phones) == 7)
    }

    @Test("Non-numeric phone ids map by list index")
    func nonNumericPhoneIDMapsByIndex() throws {
        let named = [
            TrustedPhoneNumber(id: "phone-a", number: "+1 555 0100"),
            TrustedPhoneNumber(id: "phone-b", number: "+1 555 0101"),
        ]
        #expect(try TwoFactorFlow.numericPhoneID("phone-b", known: named) == 2)
    }

    @Test("Unknown phone ids fail instead of falling back to 1")
    func unknownPhoneIDThrows() {
        #expect(throws: DeveloperPortalError.self) {
            _ = try TwoFactorFlow.numericPhoneID("missing", known: phones)
        }
    }

    @Test("At most two 2FA rounds per sign-in")
    func twoFactorRoundBudget() {
        #expect(TwoFactorFlow.canStartRound(0))
        #expect(TwoFactorFlow.canStartRound(1))
        #expect(!TwoFactorFlow.canStartRound(2))
        #expect(!TwoFactorFlow.canStartRound(3))
    }
}
