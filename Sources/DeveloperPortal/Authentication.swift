//
//  Authentication.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import GSACryptoKit

/// 一次登录过程中需要跨递归调用传递的显式状态（替代原 TaskLocal 隐式状态）。
private struct AuthenticationProgress: Sendable {
    var pushedCodeHandled = false
    var twoFactorRounds = 0
}

/// GSA 返回的可重试状态（429/503/433）。用类型判断，而不是匹配错误文案。
private struct RetryableHTTPError: LocalizedError {
    let status: Int
    let payload: String

    var errorDescription: String? {
        "Apple returned HTTP \(status) during sign-in. Please wait a moment and try again."
    }
}

public extension DeveloperPortal {

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      machinePassword: String? = nil,
                      accountRepairHandler: DeveloperPortal.AccountRepairHandler = DeveloperPortal.defaultAccountRepairHandler,
                      verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession
    {
        try await authenticate(
            appleID: unsanitizedAppleID,
            password: password,
            anisetteData: anisetteData,
            xcodeVersion: xcodeVersion,
            machinePassword: machinePassword,
            accountRepairHandler: accountRepairHandler,
            verificationHandler: verificationHandler,
            progress: AuthenticationProgress()
        )
    }

    private func authenticate(appleID unsanitizedAppleID: String,
                              password: String,
                              anisetteData: AnisetteData,
                              xcodeVersion: String,
                              machinePassword: String?,
                              accountRepairHandler: DeveloperPortal.AccountRepairHandler,
                              verificationHandler: DeveloperPortal.VerificationHandler?,
                              progress: AuthenticationProgress) async throws -> AuthSession
    {
        let sanitizedAppleID = unsanitizedAppleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        debugLog("[SideSign] Starting authenticate...")
        verboseLog("[SideSign] Authenticating Apple ID: \(sanitizedAppleID)")

        // SideInstaller AnisetteData::get_client_provided_data — only these anisette fields in CPD.
        // Extra LU/RINFO/SRL/Client-Time in CPD has been correlated with -80045 on mismatched builds.
        let clientDictionary: [String: any Sendable] = [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": customHeaders.grandSlam.service.isEmpty ? "iCloud" : customHeaders.grandSlam.service,
            "loc": anisetteData.locale.isEmpty ? "en_US" : anisetteData.locale,
            "X-Mme-Device-Id": anisetteData.deviceID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
        ]

        guard let srpClient = SRPClient(),
              let publicKey = srpClient.startAuthentication()
        else {
            debugLog("[SideSign] Failed to start SRPClient / generate public key A")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to start SRPClient / generate public key A")
        }

        verboseLog("[SideSign] SRPClient started. Generated public key A: \(publicKey.hexEncodedString())")

        // 1. Send authentication 'init' request
        let initParameters: [String: any Sendable] = [
            "A2k": publicKey,
            "cpd": clientDictionary,
            "ps": ["s2k", "s2k_fo"],
            "o": "init",
            "u": sanitizedAppleID
        ]

        debugLog("[SideSign] Sending authentication 'init' request...")
        let initResponse = try await sendAuthenticationRequest(parameters: initParameters, anisetteData: anisetteData)

        guard let c = initResponse["c"] as? String,
              let salt = initResponse["s"] as? Data,
              let iterations = initResponse["i"] as? Int,
              let serverPublicKey = initResponse["B"] as? Data
        else {
            let payload = prettyJSONString(from: initResponse)
            debugLog("[SideSign] Failed to parse authentication init response dictionary: missing c/s/i/B parameters")
            throw ServerError.badServerResponse(reason: "Auth init response missing c/s/i/B parameters", jsonPayload: payload)
        }

        verboseLog("""
        [SideSign] Received init response:
          • c: \(c)
          • sp: \(initResponse["sp"] as? String ?? "nil")
          • salt: \(salt.hexEncodedString())
          • iterations: \(iterations)
          • B: \(serverPublicKey.hexEncodedString())
        """)

        let sp = initResponse["sp"] as? String
        let isHexadecimal = (sp == "s2k_fo")

        guard let passwordData = password.data(using: .utf8),
              let digest = CryptoUtilities.sha256(passwordData) else {
            debugLog("[SideSign] Failed to compute SHA256 of password")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute SHA256 of password")
        }

        let inputDigest: Data = isHexadecimal ? Data(digest.hexEncodedString().utf8) : digest
        guard let derivedPasswordKey = CryptoUtilities.pbkdf2SHA256(
            password: inputDigest,
            salt: salt,
            rounds: iterations,
            outputLength: digest.count
        ) else {
            debugLog("[SideSign] Failed to derive PBKDF2 password key")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to derive PBKDF2 password key")
        }

        guard let verificationMessage = srpClient.processChallenge(
            username: sanitizedAppleID,
            password: derivedPasswordKey,
            salt: salt,
            serverPublicKey: serverPublicKey
        ) else {
            debugLog("[SideSign] SRP challenge processing failed")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "SRP challenge processing failed")
        }

        debugLog("[SideSign] Initiating SRP authentication step 2 (complete)...")
        verboseLog("[SideSign] Generated verification message M1: \(verificationMessage.hexEncodedString())")

        // 2. Send authentication 'complete' request
        let completeParameters: [String: any Sendable] = [
            "c": c,
            "cpd": clientDictionary,
            "M1": verificationMessage,
            "o": "complete",
            "u": sanitizedAppleID
        ]

        let completeResponseDictionary = try await sendAuthenticationRequest(parameters: completeParameters, anisetteData: anisetteData)
        debugLog("[SideSign] SRP complete step finished.")

        guard let encryptedData = completeResponseDictionary["spd"] as? Data else {
            let payload = prettyJSONString(from: completeResponseDictionary)
            debugLog("[SideSign] Missing encrypted data 'spd' in auth complete response: \(payload)")
            throw ServerError.missingKey(key: "spd", jsonPayload: payload)
        }

        guard let serverVerificationMessage = completeResponseDictionary["M2"] as? Data else {
            let payload = prettyJSONString(from: completeResponseDictionary)
            debugLog("[SideSign] Missing server verification message 'M2' in auth complete response: \(payload)")
            throw ServerError.missingKey(key: "M2", jsonPayload: payload)
        }

        verboseLog("""
        [SideSign] Received SPD payload:
          • Encrypted SPD bytes: \(encryptedData.count)
          • M2: \(serverVerificationMessage.hexEncodedString())
        """)

        guard srpClient.verifyServerProof(serverVerificationMessage) else {
            debugLog("[SideSign] Server M2 verification message validation failed")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Server verification proof (M2) mismatch")
        }

        guard let sharedSecret = srpClient.sessionKey() else {
            debugLog("[SideSign] Failed to obtain session key from SRPClient")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Missing session key")
        }

        guard let spdKey = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data key:"]),
              let spdIV = CryptoUtilities.hmacSHA256(key: sharedSecret, strings: ["extra data iv:"]),
              let decryptedData = CryptoUtilities.aesCBCDecrypt(key: spdKey, iv: spdIV, ciphertext: encryptedData)
        else {
            debugLog("[SideSign] Decryption of SPD payload failed")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-CBC decrypt SPD payload")
        }

        guard let decryptedDictionary = parsePlistOrJSON(decryptedData) else {
            let rawDecrypted = prettyJSONString(from: decryptedData)
            debugLog("[SideSign] Decrypted payload format is invalid (neither Plist nor JSON)")
            throw ServerError.invalidResponseFormat(rawPayload: rawDecrypted)
        }

        let adsid = decryptedDictionary["adsid"] as? String
        let dsidString = (decryptedDictionary["dsid"] as? CustomStringConvertible)?.description
        guard let dsid = adsid ?? dsidString else {
            let jsonStr = prettyJSONString(from: decryptedDictionary)
            debugLog("[SideSign] Decrypted dictionary missing adsid/dsid")
            throw ServerError.missingKey(key: "adsid", jsonPayload: jsonStr)
        }

        let gsIdmsToken = decryptedDictionary["GsIdmsToken"] as? String
        let rawIdmsToken = decryptedDictionary["idmsToken"] as? String
        guard let idmsToken = gsIdmsToken ?? rawIdmsToken else {
            let jsonStr = prettyJSONString(from: decryptedDictionary)
            debugLog("[SideSign] Decrypted dictionary missing GsIdmsToken/idmsToken")
            throw ServerError.missingKey(key: "GsIdmsToken", jsonPayload: jsonStr)
        }

        verboseLog("[SideSign] Parse complete. dsid: \(dsid), token: \(idmsToken)")

        // 2FA auth type
        let statusDictionary = completeResponseDictionary["Status"] as? [String: any Sendable]
        let authType = (statusDictionary?["au"] as? String)
           ?? (completeResponseDictionary["au"] as? String)
           ?? ((statusDictionary?["hsc"] as? Int) == 409 ? "pushedCode" : nil)
        verboseLog("[SideSign] Authentication status type: \(authType ?? "nil")")

        // 身份由调用方提供（SideStore 侧真值来自 AppConstants），库内不再做二次改写，
        // 避免同一会话出现多套 client-info / User-Agent。
        let locked = (
            clientInfo: anisetteData.clientInfo.trimmingCharacters(in: .whitespacesAndNewlines),
            userAgent: anisetteData.userAgent.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        let twoFactorAuthContext = TwoFactorAuthContext(
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: anisetteData,
            xcodeVersion: xcodeVersion,
            lockedClientInfo: locked.clientInfo,
            lockedUserAgent: locked.userAgent
        )

        switch authType {
            case "trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone", "pushedCode":
                let pushedCode = authType == "pushedCode"
                guard !pushedCode || !progress.pushedCodeHandled else {
                    throw DeveloperPortalError.requiresTwoFactorAuthentication
                }
                // 最多允许两轮 2FA（首轮 + 重登后 Apple 再要求一次），避免无限循环。
                guard progress.twoFactorRounds < 2 else {
                    debugLog("[SideSign] Apple requested 2FA \(progress.twoFactorRounds + 1) times — aborting")
                    throw DeveloperPortalError.tooManyAttempts(
                        cause: "Apple asked for another verification code after a successful round. Please wait a moment and try signing in again.")
                }
                var nextProgress = progress
                nextProgress.twoFactorRounds += 1
                if pushedCode { nextProgress.pushedCodeHandled = true }

                let isTrustedDevice = pushedCode || authType == "trustedDeviceSecondaryAuth" || authType == "trustedDevice"
                try await handle2FARequest(
                    isTrustedDevice: isTrustedDevice,
                    completeResponseDictionary: completeResponseDictionary,
                    statusDictionary: statusDictionary,
                    context: twoFactorAuthContext,
                    verificationHandler: verificationHandler,
                    codeAlreadySent: pushedCode
                )

                // 2FA 后用同一身份重新登录；有限次退避，总时长不超过 60s。
                let lockedCI = twoFactorAuthContext.lockedClientInfo
                let lockedUA = twoFactorAuthContext.lockedUserAgent
                let post2FADelays: [UInt64] = [1_000_000_000, 3_000_000_000, 5_000_000_000]
                let deadline = Date().addingTimeInterval(60)
                var lastPost2FAError: Error?

                for (index, delay) in post2FADelays.enumerated() {
                    try await Task.sleep(nanoseconds: delay)
                    guard Date() < deadline else { break }

                    // get_anisette_data before login again（刷新 OTP，保持同一台机器）
                    var post2FAAnisette = await Self.refreshOTPKeepingMachine(
                        anisetteData,
                        lockedCI: lockedCI,
                        lockedUA: lockedUA
                    )
                    post2FAAnisette.clientInfo = lockedCI
                    post2FAAnisette.userAgent = lockedUA
                    post2FAAnisette.clientTime = Self.timestamp()

                    debugLog("[SideSign] Post-2FA re-login attempt \(index + 1)/\(post2FADelays.count) same-identity client=\(lockedCI.prefix(48))...")

                    do {
                        return try await authenticate(
                            appleID: unsanitizedAppleID,
                            password: password,
                            anisetteData: post2FAAnisette,
                            xcodeVersion: xcodeVersion,
                            machinePassword: machinePassword,
                            accountRepairHandler: accountRepairHandler,
                            verificationHandler: verificationHandler,
                            progress: nextProgress
                        )
                    } catch let retryable as RetryableHTTPError {
                        debugLog("[SideSign] Post-2FA re-login attempt \(index + 1) got HTTP \(retryable.status), retrying")
                        lastPost2FAError = retryable
                        continue
                    }
                }
                throw lastPost2FAError ?? ServerError.badServerResponse(
                    reason: "Apple rejected the sign-in after verification. Please wait a moment and try again.",
                    jsonPayload: "")

            case "repair":
                let directRepairURL = completeResponseDictionary["repairUrl"] as? String
                let directURL = completeResponseDictionary["url"] as? String
                let statusURL = (statusDictionary?["url"] as? String)
                let repairURLString = directRepairURL ?? directURL ?? statusURL
                let repairURL = repairURLString.flatMap { URL(string: $0) } ?? Constants.URLs.developerAccount

                let rawMessage = (statusDictionary?["em"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)

                let message: String
                if let rawMessage, !rawMessage.isEmpty {
                    message = rawMessage
                } else {
                    message = Constants.defaultAccountRepairMessage
                }

                debugLog("[SideSign] Account repair required: \(message) (url: \(repairURL.absoluteString)). Prompting accountRepairHandler...")
                let decision = try await accountRepairHandler(repairURL, message)

                if decision == .cancel {
                    debugLog("[SideSign] Account repair cancelled by caller.")
                    throw DeveloperPortalError.accountRepairRequired(url: repairURL, message: message)
                }

                debugLog("[SideSign] Account repair acknowledged by caller. Continuing to fetch app tokens...")

            default:
                break
        }

        guard let sessionKey = decryptedDictionary["sk"] as? Data else {
            debugLog("[SideSign] Decrypted dictionary missing 'sk' key for apptokens")
            throw ServerError.missingKey(key: "sk", jsonPayload: prettyJSONString(from: decryptedDictionary))
        }

        guard let c = decryptedDictionary["c"] as? Data else {
            debugLog("[SideSign] Decrypted dictionary missing 'c' key for apptokens")
            throw ServerError.missingKey(key: "c", jsonPayload: prettyJSONString(from: decryptedDictionary))
        }

        let app = customHeaders.grandSlam.authApp
        guard let checksum = CryptoUtilities.hmacSHA256(key: sessionKey, strings: ["apptokens", dsid, app]) else {
            debugLog("[SideSign] Failed to compute apptokens checksum")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to compute apptokens checksum")
        }

        let appTokensParameters: [String: any Sendable] = [
            "app": [app],
            "c": c,
            "checksum": checksum,
            "cpd": clientDictionary,
            "o": "apptokens",
            "t": idmsToken,
            "u": dsid
        ]

        let fetchedToken = try await fetchAuthToken(app: app, parameters: appTokensParameters, sessionKey: sessionKey, anisetteData: anisetteData)
        let session = Session(
            dsid: dsid,
            authToken: fetchedToken.token,
            anisetteData: anisetteData,
            xcodeVersion: xcodeVersion,
            machinePassword: machinePassword,
            creationDate: fetchedToken.creationDate,
            expirationDate: fetchedToken.expirationDate,
            timeToLive: fetchedToken.timeToLive
        )
        let account = try await fetchAccount(session: session)
        return AuthSession(account: account, session: session)
    }

    func sendAuthenticationRequest(parameters requestParameters: [String: any Sendable], anisetteData: AnisetteData) async throws -> [String: any Sendable] {
        let requestURL = Constants.URLs.grandSlamAuth
        let h = customHeaders

        let parameters: [String: any Sendable] = [
            "Header": ["Version": h.grandSlam.headerVersion],
            "Request": requestParameters
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = plistData

        // 身份由调用方的 anisetteData 唯一决定（SideStore 侧真值来自 AppConstants），
        // 库内不再内置任何设备字面量，避免同一会话出现两套身份。
        let clientInfo = anisetteData.clientInfo
        let userAgent = anisetteData.userAgent

        func applyGrandSlamHeaders(_ req: inout URLRequest, clientInfo: String, userAgent: String) {
            // SideInstaller GrandSlam base_headers + get_headers (Device-Id, MD, MD-M only)
            let allHeaders: [String: String] = [
                "Content-Type": "text/x-xml-plist",
                "Accept": "text/x-xml-plist",
                "User-Agent": userAgent,
                "X-Mme-Client-Info": clientInfo,
                "X-Xcode-Version": "14.2 (14C18)",
                "X-Apple-App-Info": "com.apple.gs.xcode.auth",
                "X-Mme-Device-Id": anisetteData.deviceID,
                "X-Apple-I-MD": anisetteData.oneTimePassword,
                "X-Apple-I-MD-M": anisetteData.machineID,
                "Connection": "close",
            ]
            allHeaders.forEach { req.setValue($1, forHTTPHeaderField: $0) }
        }

        applyGrandSlamHeaders(&request, clientInfo: clientInfo, userAgent: userAgent)
        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] sendAuthenticationRequest HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        // SideInstaller: retry 429/503 时保持同一身份，仅做退避。
        let retryDelays: [UInt64] = [2_000_000_000, 5_000_000_000, 10_000_000_000]
        var data = Data()
        var response: URLResponse = URLResponse(url: Constants.URLs.grandSlamAuth, mimeType: nil, expectedContentLength: 0, textEncodingName: nil)
        var statusCode = 0
        var attempt = 0
        while true {
            do {
                (data, response) = try await session.data(for: request)
            } catch {
                debugLog("[SideSign] sendAuthenticationRequest network error: \(error)")
                throw error
            }
            let httpResponse = response as? HTTPURLResponse
            statusCode = httpResponse?.statusCode ?? 0
            let retryable = statusCode == HTTPStatusCodes.tooManyRequests || statusCode == 503 || statusCode == 433
            if retryable, attempt < retryDelays.count {
                let delay = retryDelays[attempt]
                debugLog("[SideSign] GrandSlam HTTP \(statusCode) — retry \(attempt + 1) in \(delay / 1_000_000_000)s client=\(clientInfo.prefix(40))...")
                try await Task.sleep(nanoseconds: delay)
                attempt += 1
                continue
            }
            break
        }

        if statusCode == HTTPStatusCodes.tooManyRequests || statusCode == 503 || statusCode == 433 {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] GrandSlam still HTTP \(statusCode) after retries: \(rawStr.prefix(200))")
            throw RetryableHTTPError(status: statusCode, payload: rawStr)
        }

        if statusCode != 0 && !(200...299).contains(statusCode) {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] GrandSlam HTTP \(statusCode): \(rawStr.prefix(200))")
            // continue to parse if body might be a plist with Status.ec; if empty/HTML, fail below
        }

        guard !data.isEmpty else {
            debugLog("[SideSign] Auth endpoint returned 0 bytes (HTTP \(statusCode))")
            throw ServerError.badServerResponse(reason: "Auth endpoint returned empty response (0 bytes)", jsonPayload: "0 bytes")
        }

        guard let responseDictionary = parsePlistOrJSON(data) else {
            let rawStr = String(data: data, encoding: .utf8) ?? data.hexEncodedString()
            debugLog("[SideSign] Auth endpoint returned invalid response format: \(rawStr)")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        let dictionary = (responseDictionary["Response"] as? [String: any Sendable]) ?? responseDictionary
        guard let status = dictionary["Status"] as? [String: any Sendable] else {
            let rawStr = prettyJSONString(from: responseDictionary)
            debugLog("[SideSign] Auth endpoint response missing 'Status': \(rawStr)")
            throw ServerError.missingKey(key: "Status", jsonPayload: rawStr)
        }

        let errorCode = status["ec"] as? Int ?? 0
        if errorCode != 0 {
            let errorDesc = status["em"] as? String
            debugLog("[SideSign] Auth endpoint returned error code \(errorCode): \(errorDesc ?? "No error message")")
            switch errorCode {
            case GrandSlamAuthErrorCodes.incorrectCredentials:
                throw DeveloperPortalError.incorrectCredentials(cause: errorDesc)
            case GrandSlamAuthErrorCodes.appSpecificPasswordRequired,
                 GrandSlamAuthErrorCodes.appSpecificPasswordRequiredFallback:
                throw DeveloperPortalError.appSpecificPasswordRequired(cause: errorDesc)
            case GrandSlamAuthErrorCodes.incorrectVerificationCode:
                throw DeveloperPortalError.incorrectVerificationCode(cause: errorDesc)
            default:
                // -80045 / -80046 = anisette identity rejected — drop saved adi so next attempt can provision clean
                if errorCode == -80045 || errorCode == -80046 || errorCode == 80045 || errorCode == 80046 {
                    UserDefaults.standard.removeObject(forKey: "SideSign.anisetteAdiBlob")
                    UserDefaults.standard.removeObject(forKey: "anisetteAdiBlob")
                    debugLog("[SideSign] Cleared adi blob after \(errorCode) — reset adi.pb in SideStore and retry once on a Mac server")
                }
                throw ServerError.underlyingError(code: errorCode, message: errorDesc ?? "Authentication failed")
            }
        }

        return dictionary
    }

    private struct FetchedAuthToken {
        let token: String
        let creationDate: Date
        let expirationDate: Date?
        let timeToLive: TimeInterval?
    }

    private func fetchAuthToken(app: String, parameters: [String: any Sendable], sessionKey: Data, anisetteData: AnisetteData) async throws -> FetchedAuthToken {
        let responseDictionary = try await sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData)

        guard let encryptedToken = responseDictionary["et"] as? Data else {
            let payload = prettyJSONString(from: responseDictionary)
            debugLog("[SideSign] fetchAuthToken missing 'et' key in response")
            throw ServerError.missingKey(key: "et", jsonPayload: payload)
        }

        guard encryptedToken.count > 35 else {
            debugLog("[SideSign] Encrypted token payload is too short (length: \(encryptedToken.count))")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Encrypted token payload is too short (\(encryptedToken.count) bytes)")
        }

        let aad = Data(encryptedToken[..<3])
        let nonce = Data(encryptedToken[3..<19])
        let ciphertext = Data(encryptedToken[19..<(encryptedToken.count - 16)])
        let tag = Data(encryptedToken[(encryptedToken.count - 16)...])

        guard let token = CryptoUtilities.aesGCMDecrypt(key: sessionKey, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag) else {
            debugLog("[SideSign] Failed to AES-GCM decrypt auth token")
            throw DeveloperPortalError.authenticationHandshakeFailed(cause: "Failed to AES-GCM decrypt auth token")
        }

        guard let tokensDictionary = parsePlistOrJSON(token) else {
            let rawStr = prettyJSONString(from: token)
            debugLog("[SideSign] Failed to parse decrypted token dictionary")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        guard let appTokens = tokensDictionary["t"] as? [String: any Sendable],
              let tokens = appTokens[app] as? [String: any Sendable],
              let authToken = tokens["token"] as? String
        else {
            let payload = prettyJSONString(from: tokensDictionary)
            debugLog("[SideSign] Decrypted tokens missing t/\(app)/token")
            throw ServerError.missingKey(key: "t/\(app)/token", jsonPayload: payload)
        }

        verboseLog("[SideSign] Decrypted GrandSlam response: \(prettyJSONString(from: sanitizeTokens(tokensDictionary)))")

        let now = Date()
        var expirationDate: Date? = nil
        var timeToLive: TimeInterval? = nil

        if let expiry = tokens["expiry"] as? Date {
            expirationDate = expiry
            timeToLive = expiry.timeIntervalSince(now)
        } else if let expiryStr = tokens["expiry"] as? String, let parsed = ISO8601DateFormatter().date(from: expiryStr) {
            expirationDate = parsed
            timeToLive = parsed.timeIntervalSince(now)
        } else if let ttl = tokens["ttl"] as? Double ?? (tokens["ttl"] as? Int).map(Double.init) {
            timeToLive = ttl
            expirationDate = now.addingTimeInterval(ttl)
        } else if let exp = tokens["expiry-date"] as? Date {
            expirationDate = exp
            timeToLive = exp.timeIntervalSince(now)
        } else if let expStr = tokens["expiry-date"] as? String, let parsed = ISO8601DateFormatter().date(from: expStr) {
            expirationDate = parsed
            timeToLive = parsed.timeIntervalSince(now)
        }

        let ttlDesc: String
        if let ttl = timeToLive {
            let days = Int(ttl / 86400)
            let hours = Int((ttl.truncatingRemainder(dividingBy: 86400)) / 3600)
            ttlDesc = "\(days)d \(hours)h (\(Int(ttl))s)"
        } else {
            ttlDesc = "unspecified"
        }

        let expiryDesc = expirationDate.map { ISO8601DateFormatter().string(from: $0) } ?? "unspecified"
        debugLog("[SideSign] Successfully obtained auth token for app: \(app) (TTL: \(ttlDesc), Expiry: \(expiryDesc))")
        return FetchedAuthToken(token: authToken, creationDate: now, expirationDate: expirationDate, timeToLive: timeToLive)
    }

    private func parseTrustedPhoneNumbers(from dict: [String: any Sendable]?) -> [TrustedPhoneNumber] {
        var results: [TrustedPhoneNumber] = []
        let list = (dict?["trustedPhoneNumbers"] as? [[String: any Sendable]])
                ?? (dict?["phoneNumbers"] as? [[String: any Sendable]])
                ?? []
        for item in list {
            if let id = (item["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                let num = (item["numberWithDialCode"] as? String)
                        ?? (item["obfuscatedNumber"] as? String)
                        ?? (item["lastTwoDigits"] as? String).map { "••\($0)" }
                        ?? "Phone \(id)"
                results.append(TrustedPhoneNumber(id: id, number: num))
            }
        }
        if results.isEmpty, let single = dict?["phoneNumber"] as? [String: any Sendable],
           let id = (single["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
            let num = (single["numberWithDialCode"] as? String)
                    ?? (single["obfuscatedNumber"] as? String)
                    ?? (single["lastTwoDigits"] as? String).map { "••\($0)" }
                    ?? "Phone \(id)"
            results.append(TrustedPhoneNumber(id: id, number: num))
        }
        return results
    }

    private func parseXMLUIAlertMessage(from data: Data) -> (title: String?, message: String?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }
        if str.contains("<pinView") {
            return (nil, nil)
        }
        guard let alertTagRange = str.range(of: #"<alert(?![^>]*\bid=)[^>]*>"#, options: .regularExpression) else {
            return (nil, nil)
        }
        let alertTag = String(str[alertTagRange])
        var title: String?
        var message: String?
        if let titleRange = alertTag.range(of: #"(?<=title=")[^"]+"#, options: .regularExpression) {
            title = String(alertTag[titleRange])
        }
        if let msgRange = alertTag.range(of: #"(?<=message=")[^"]+"#, options: .regularExpression) {
            message = String(alertTag[msgRange])
        }
        return (title, message)
    }

    private func parseXMLUIServerInfo(from data: Data) -> (phoneID: String?, mode: String?) {
        guard let str = String(data: data, encoding: .utf8) else { return (nil, nil) }
        guard let range = str.range(of: #"<serverInfo[^>]*>"#, options: .regularExpression) else { return (nil, nil) }
        let tag = String(str[range])
        var phoneID: String?
        var mode: String?
        if let idRange = tag.range(of: #"(?<=phoneNumber\.id=")[^"]+"#, options: .regularExpression) {
            phoneID = String(tag[idRange])
        }
        if let modeRange = tag.range(of: #"(?<=mode=")[^"]+"#, options: .regularExpression) {
            mode = String(tag[modeRange])
        }
        return (phoneID, mode)
    }

    /// True when Apple's 2FA page refused SMS/voice (often shown as "Could not connect to iCloud").
    private static func isPhoneOrICloudRefuse(_ text: String?) -> Bool {
        guard let t = text?.lowercased(), !t.isEmpty else { return false }
        return t.contains("icloud")
            || t.contains("could not connect")
    }

    /// Never show Apple's "Could not connect to iCloud" / internal markers to the user.
    private static func sanitize2FAUserMessage(_ text: String?) -> String {
        guard let text, !text.isEmpty else { return "Apple didn't confirm sending a code to your Apple devices. If one arrived, enter it; if not, try another way." }
        if isPhoneOrICloudRefuse(text) {
            return "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices."
        }
        let lower = text.lowercased()
        if lower.contains("icloud") {
            return "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices."
        }
        return text
    }

    private func parseXMLUIObfuscatedNumber(from data: Data) -> String? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }
        let patterns = [
            #"(?:to|at)\s+([+•\d\s\(\)-]{4,25})[.\s<]"#,
            #"([+•\d\s\(\)-]*[•]+[+•\d\s\(\)-]*)"#
        ]
        for pattern in patterns {
            if let matchRange = str.range(of: pattern, options: .regularExpression) {
                let matched = String(str[matchRange])
                    .replacingOccurrences(of: "to ", with: "")
                    .replacingOccurrences(of: "at ", with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: ". <\n\r\t"))
                if matched.contains("•") && matched.count >= 3 {
                    return matched
                }
            }
        }
        return nil
    }

    private struct TwoFactorAuthContext {
        let dsid: String
        let idmsToken: String
        let anisetteData: AnisetteData
        let xcodeVersion: String
        /// SideInstaller: same device from start to finish — locked at first GrandSlam request
        let lockedClientInfo: String
        let lockedUserAgent: String
    }

    private struct TwoFactorAuthPhoneCodeResponse {
        let phoneID: String
        let activeMode: String
        let phoneNumbers: [TrustedPhoneNumber]
        let statusCode: Int
    }

    private enum TwoFactorAuthValidationResult {
        case success
        case retry(message: String)
    }

    // MARK: - SideInstaller LoginState (apple_account.rs) full 2FA

    /// SideInstaller `LoginState` for the 2FA portion of sign-in.
    private enum SideInstallerLoginState {
        case needsDevice2FA
        case needsDevice2FAVerification
        case needsPhone2FA(phoneID: String, mode: TwoFactorDeliveryMode)
        case needsPhone2FAVerification(phoneID: String, mode: TwoFactorDeliveryMode)
    }

    private func handle2FARequest(isTrustedDevice: Bool,
                            completeResponseDictionary: [String: any Sendable],
                            statusDictionary: [String: any Sendable]?,
                            context: TwoFactorAuthContext,
                            verificationHandler: VerificationHandler?,
                            codeAlreadySent: Bool = false) async throws
    {
        guard let verificationHandler else {
            throw DeveloperPortalError.requiresTwoFactorAuthentication
        }

        var phoneNumbers = parseTrustedPhoneNumbers(from: completeResponseDictionary)
        if phoneNumbers.isEmpty, let statusDictionary {
            phoneNumbers = parseTrustedPhoneNumbers(from: statusDictionary)
        }
        let phoneID0 = phoneNumbers.first?.id ?? "1"
        var ctx = context
        var pendingError: String? = nil
        var codeRequests = 0
        var verificationAttempts = 0

        // SideStore only shows Apple Devices / SMS / Phone Call for
        // TwoFactorRequest.selectDeliveryMethod — not for .trustedDevice
        // (that is code-entry + "Other Options…"). Ask for the method first.
        let preferredMode: TwoFactorDeliveryMode =
            (codeAlreadySent || isTrustedDevice) ? .trustedDevice : .sms
        let initialChoice = try await verificationHandler(
            .selectDeliveryMethod(preferredMode: preferredMode, phoneNumbers: phoneNumbers)
        )


        var state: SideInstallerLoginState
        switch initialChoice {
        case .requestTrustedDevice:
            state = codeAlreadySent ? .needsDevice2FAVerification : .needsDevice2FA
        case .requestSMS(let id):
            state = .needsPhone2FA(phoneID: id.isEmpty ? phoneID0 : id, mode: .sms)
        case .requestVoice(let id):
            state = .needsPhone2FA(phoneID: id.isEmpty ? phoneID0 : id, mode: .voice)
        case .verificationCode(_):
            // Unexpected at method selection — treat as cancel
            throw DeveloperPortalError.userCancelled
        case .cancel:
            throw DeveloperPortalError.userCancelled
        }

        let phoneMsg = "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices."
        let deviceMsg = "Apple didn't confirm sending a code to your Apple devices. If one arrived, enter it; if not, try another way."

        while true {
            switch state {
            case .needsDevice2FA:
                do { try await sendTrustedDevice2FACodeRequest(context: ctx) } catch {
                    debugLog("[SideSign] SI NeedsDevice2FA soft: \(error)")
                    pendingError = deviceMsg
                }
                state = .needsDevice2FAVerification

            case .needsPhone2FA(let phoneID, let mode):
                codeRequests += 1
                guard codeRequests <= 5 else {
                    throw DeveloperPortalError.tooManyAttempts(
                        cause: "Too many verification codes requested for this sign-in. Please try again later.")
                }
                do {
                    let result = try await sendPhone2FACodeRequest(
                        mode: mode.rawValue, phoneID: phoneID, knownPhoneNumbers: phoneNumbers, context: ctx)
                    phoneNumbers = result.phoneNumbers.isEmpty ? phoneNumbers : result.phoneNumbers
                    pendingError = nil
                    state = .needsPhone2FAVerification(phoneID: result.phoneID, mode: mode)
                } catch DeveloperPortalError.invalid2FAResponse {
                    debugLog("[SideSign] phone 2FA (\(mode.rawValue)) refused — falling back to devices")
                    pendingError = phoneMsg
                    state = .needsDevice2FA
                } catch {
                    debugLog("[SideSign] phone 2FA (\(mode.rawValue)) failed: \(error)")
                    throw error
                }

            case .needsDevice2FAVerification:
                let err = pendingError
                pendingError = nil
                let response = try await verificationHandler(.trustedDevice(error: err))
                switch response {
                case .requestTrustedDevice:
                    state = .needsDevice2FA
                case .requestSMS(let id):
                    state = .needsPhone2FA(phoneID: id, mode: .sms)
                case .requestVoice(let id):
                    state = .needsPhone2FA(phoneID: id, mode: .voice)
                case .verificationCode(let code):
                    verificationAttempts += 1
                    guard verificationAttempts <= 5 else {
                        throw DeveloperPortalError.tooManyAttempts(
                            cause: "Too many verification codes entered for this sign-in. Please try again later.")
                    }
                    let refreshed = await Self.refreshOTPKeepingMachine(
                        ctx.anisetteData, lockedCI: ctx.lockedClientInfo, lockedUA: ctx.lockedUserAgent)
                    ctx = TwoFactorAuthContext(
                        dsid: ctx.dsid, idmsToken: ctx.idmsToken, anisetteData: refreshed,
                        xcodeVersion: ctx.xcodeVersion,
                        lockedClientInfo: ctx.lockedClientInfo, lockedUserAgent: ctx.lockedUserAgent)
                    do {
                        switch try await validateTrustedDevice2FACode(code: code, context: ctx) {
                        case .success:
                            return
                        case .retry(let message):
                            pendingError = Self.sanitize2FAUserMessage(message)
                            state = .needsDevice2FAVerification
                        }
                    } catch {
                        debugLog("[SideSign] device 2FA verify error: \(error)")
                        pendingError = Self.sanitize2FAUserMessage("\(error)")
                        state = .needsDevice2FAVerification
                    }
                case .cancel:
                    throw DeveloperPortalError.userCancelled
                }

            case .needsPhone2FAVerification(let phoneID, let mode):
                let err = pendingError
                pendingError = nil
                // 发码渠道与提示渠道、验证渠道保持一致（语音码不能按短信验证）。
                let request: TwoFactorRequest = mode == .voice
                    ? .voice(phoneNumbers: phoneNumbers, activeID: phoneID, error: err)
                    : .sms(phoneNumbers: phoneNumbers, activeID: phoneID, error: err)
                let response = try await verificationHandler(request)
                switch response {
                case .requestTrustedDevice:
                    state = .needsDevice2FA
                case .requestSMS(let id):
                    state = .needsPhone2FA(phoneID: id, mode: .sms)
                case .requestVoice(let id):
                    state = .needsPhone2FA(phoneID: id, mode: .voice)
                case .verificationCode(let code):
                    verificationAttempts += 1
                    guard verificationAttempts <= 5 else {
                        throw DeveloperPortalError.tooManyAttempts(
                            cause: "Too many verification codes entered for this sign-in. Please try again later.")
                    }
                    let refreshed = await Self.refreshOTPKeepingMachine(
                        ctx.anisetteData, lockedCI: ctx.lockedClientInfo, lockedUA: ctx.lockedUserAgent)
                    ctx = TwoFactorAuthContext(
                        dsid: ctx.dsid, idmsToken: ctx.idmsToken, anisetteData: refreshed,
                        xcodeVersion: ctx.xcodeVersion,
                        lockedClientInfo: ctx.lockedClientInfo, lockedUserAgent: ctx.lockedUserAgent)
                    do {
                        switch try await validatePhone2FACode(
                            code: code, phoneID: phoneID, mode: mode.rawValue, context: ctx) {
                        case .success:
                            return
                        case .retry(let message):
                            if Self.isPhoneOrICloudRefuse(message) {
                                pendingError = phoneMsg
                                state = .needsDevice2FA
                            } else {
                                pendingError = Self.sanitize2FAUserMessage(message)
                                state = .needsPhone2FAVerification(phoneID: phoneID, mode: mode)
                            }
                        }
                    } catch DeveloperPortalError.invalid2FAResponse {
                        debugLog("[SideSign] phone 2FA verify refused (\(mode.rawValue))")
                        pendingError = phoneMsg
                        state = .needsDevice2FA
                    } catch {
                        debugLog("[SideSign] phone 2FA verify error (\(mode.rawValue)): \(error)")
                        throw error
                    }
                case .cancel:
                    throw DeveloperPortalError.userCancelled
                }
            }
        }
    }

    private func sendTrustedDevice2FACodeRequest(context: TwoFactorAuthContext) async throws {
        debugLog("[SideSign] Requesting trusted device 2FA code...")
        verboseLog("[SideSign] sendTrustedDevice2FACodeRequest for dsid: \(context.dsid)")

        var request = makeTwoFactorAuthRequest(url: Constants.URLs.trustedDevice, context: context)
        request.httpMethod = "GET"

        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] sendTrustedDevice2FACodeRequest HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        do {
            let (data, httpResponse) = try await performTwoFactorRequest(request, actionName: "sendTrustedDevice2FACodeRequest")
            let statusCode = httpResponse.safeStatusCode
            let rawPreview = String(data: data, encoding: .utf8) ?? ""
            // SideInstaller DEVICE_CODE_UNCONFIRMED: never throw — always allow code entry
            if statusCode != HTTPStatusCodes.ok
                || rawPreview.lowercased().contains("icloud")
                || rawPreview.lowercased().contains("could not connect")
            {
                debugLog("[SideSign] Trusted-device request soft-fail (HTTP \(statusCode)); prompting for code if one arrived")
            } else {
                debugLog("[SideSign] Trusted-device code request accepted")
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch let urlError as URLError {
            // 传输层失败不应被当作"已发码"，否则用户会对着不会到达的验证码等待
            debugLog("[SideSign] Trusted-device request transport error: \(urlError)")
            throw urlError
        } catch {
            debugLog("[SideSign] Trusted-device request error soft-fail: \(error)")
        }
    }

    private func sendPhone2FACodeRequest(mode requestedMode: String,
                                      phoneID requestedPhoneID: String? = nil,
                                      knownPhoneNumbers: [TrustedPhoneNumber] = [],
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthPhoneCodeResponse
    {
        debugLog("[SideSign] Requesting secondary/phone 2FA code (mode: \(requestedMode), phoneID: \(requestedPhoneID ?? "auto"))...")
        verboseLog("[SideSign] sendPhone2FACodeRequest for dsid: \(context.dsid), requestedMode: \(requestedMode), phoneID: \(requestedPhoneID ?? "nil")")

        let sanitizedPhoneID: String = {
            if let id = requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
                return id
            }
            return "1"
        }()

        // SideInstaller: PUT JSON to https://gsa.apple.com/auth/verify/phone
        let phoneURL = URL(string: "https://gsa.apple.com/auth/verify/phone")!
        var request = makeTwoFactorAuthRequest(url: phoneURL, context: context)
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        // Apple 的 phone id 是数字；非数字时按已知号码列表索引映射，映射不到则明确报错，
        // 不能静默回退到 1 号号码。
        let phoneIdValue: Int
        if let parsed = Int(sanitizedPhoneID) {
            phoneIdValue = parsed
        } else if let index = knownPhoneNumbers.firstIndex(where: {
            $0.id.trimmingCharacters(in: .whitespacesAndNewlines) == sanitizedPhoneID
        }) {
            phoneIdValue = index + 1
        } else {
            throw DeveloperPortalError.invalidParameters(cause: "Unsupported phone id: \(sanitizedPhoneID)")
        }
        let jsonBody: [String: Any] = [
            "phoneNumber": ["id": phoneIdValue],
            "mode": requestedMode
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: jsonBody)

        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] sendPhone2FACodeRequest HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        let (data, httpResponse) = try await performTwoFactorRequest(request, actionName: "sendPhone2FACodeRequest")
        let statusCode = httpResponse.safeStatusCode

        let rawStr = prettyJSONString(from: data)
        verboseLog("[SideSign] sendPhone2FACodeRequest raw response (HTTP \(statusCode)): \(rawStr)")

        // 仅把 Apple 明确拒绝"电话/语音投递"的响应归类为渠道被拒；
        // 5xx、网关错误、解析失败等保留真实原因，避免全部伪装成"Apple 不发短信"。
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        let alertCombined = [xmluiTitle, xmluiMessage]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ": ")
        let alertLower = alertCombined.lowercased()
        let refused = statusCode == 401 || statusCode == 403 || statusCode == 423
            || alertLower.contains("icloud")
            || alertLower.contains("could not connect")
            || alertLower.contains("forbidden")
        if refused {
            if !alertCombined.isEmpty {
                debugLog("[SideSign] sendPhone2FACodeRequest Apple refused phone code (HTTP \(statusCode)): \(alertCombined)")
            } else {
                debugLog("[SideSign] sendPhone2FACodeRequest refused (HTTP \(statusCode), empty body)")
            }
            throw DeveloperPortalError.invalid2FAResponse(
                cause: alertCombined.isEmpty ? nil : Self.sanitize2FAUserMessage(alertCombined))
        }
        if (xmluiTitle != nil || xmluiMessage != nil), statusCode == HTTPStatusCodes.ok {
            debugLog("[SideSign] sendPhone2FACodeRequest alert from Apple (HTTP \(statusCode)): \(alertCombined)")
            throw DeveloperPortalError.invalid2FAResponse(
                cause: alertCombined.isEmpty ? nil : Self.sanitize2FAUserMessage(alertCombined))
        }

        let responseDict = parsePlistOrJSON(data)
        let errorCode = responseDict?["ec"] as? Int ?? 0
        let errorMsg = (responseDict?["em"] as? String)
                   ?? ((responseDict?["Status"] as? [String: any Sendable])?["em"] as? String)

        // serviceErrors / em may also say Could not connect to iCloud
        let emLower = (errorMsg ?? "").lowercased()
        if emLower.contains("icloud") || emLower.contains("could not connect") {
            debugLog("[SideSign] sendPhone2FACodeRequest service error iCloud refuse: \(errorMsg ?? "")")
            throw DeveloperPortalError.invalid2FAResponse(cause: Self.sanitize2FAUserMessage(errorMsg))
        }

        if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts
            || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested
            || errorCode == GrandSlamAuthErrorCodes.rateLimited
            || statusCode == HTTPStatusCodes.tooManyRequests
        {
            let msg = errorMsg ?? "Verification codes cannot be sent to this phone number at this time. Please try again later."
            debugLog("[SideSign] sendPhone2FACodeRequest rate-limited (\(errorCode), HTTP \(statusCode)): \(msg)")
            throw DeveloperPortalError.tooManyAttempts(cause: msg)
        } else if errorCode != 0 {
            let msg = errorMsg ?? "Failed to request verification code from Apple."
            debugLog("[SideSign] sendPhone2FACodeRequest error (\(errorCode), HTTP \(statusCode)): \(msg)")
            throw ServerError.underlyingError(code: errorCode, message: Self.sanitize2FAUserMessage(msg))
        }

        guard statusCode == HTTPStatusCodes.ok else {
            let reason = errorMsg ?? HTTPStatusCodes.localizedDescription(for: statusCode)
            debugLog("[SideSign] sendPhone2FACodeRequest failed (HTTP \(statusCode)): \(reason)")
            // 真实失败原因（5xx / 网关 / 其他）不再伪装成电话被拒
            throw ServerError.badServerResponse(
                reason: "Phone 2FA request failed (HTTP \(statusCode)): \(reason)",
                jsonPayload: rawStr)
        }

        var parsedNumbers = parseTrustedPhoneNumbers(from: responseDict)
        if parsedNumbers.isEmpty {
            parsedNumbers = knownPhoneNumbers
        }
        let singlePhoneDict = responseDict?["phoneNumber"] as? [String: any Sendable]
        let phoneListFirst = (responseDict?["phoneNumbers"] as? [[String: any Sendable]])?.first
        let trustedPhoneListFirst = (responseDict?["trustedPhoneNumbers"] as? [[String: any Sendable]])?.first
        let phoneDict = singlePhoneDict ?? phoneListFirst ?? trustedPhoneListFirst

        let (xmluiServerPhoneID, xmluiServerMode) = parseXMLUIServerInfo(from: data)

        let rawPhoneID = (phoneDict?["id"] as? CustomStringConvertible)?.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedPhoneID: String? = (rawPhoneID?.isEmpty == false) ? rawPhoneID : xmluiServerPhoneID
        let resolvedRequestedID: String? = (requestedPhoneID?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false) ? requestedPhoneID : nil

        let phoneID = resolvedPhoneID ?? resolvedRequestedID ?? parsedNumbers.first?.id ?? "1"
        let activeMode = (phoneDict?["mode"] as? String) ?? xmluiServerMode ?? requestedMode

        let numberWithDialCode = phoneDict?["numberWithDialCode"] as? String
        let obfuscatedNumber = phoneDict?["obfuscatedNumber"] as? String
        let lastTwoDigits = (phoneDict?["lastTwoDigits"] as? String).map { "••\($0)" }
        let xmluiNumber = parseXMLUIObfuscatedNumber(from: data)
        let matchedNumber = parsedNumbers.first(where: { $0.id == phoneID })?.number

        let numberObfuscated = numberWithDialCode
                            ?? obfuscatedNumber
                            ?? lastTwoDigits
                            ?? xmluiNumber
                            ?? matchedNumber
                            ?? ""
        if let idx = parsedNumbers.firstIndex(where: { $0.id == phoneID }), !numberObfuscated.isEmpty {
            parsedNumbers[idx] = TrustedPhoneNumber(id: phoneID, number: numberObfuscated)
        } else if parsedNumbers.isEmpty && !numberObfuscated.isEmpty {
            parsedNumbers = [TrustedPhoneNumber(id: phoneID, number: numberObfuscated)]
        }
        debugLog("[SideSign] sendPhone2FACodeRequest received phone response (id: \(phoneID), mode: \(activeMode), number: \(numberObfuscated), total phones: \(parsedNumbers.count))")

        return TwoFactorAuthPhoneCodeResponse(
            phoneID: phoneID,
            activeMode: activeMode,
            phoneNumbers: parsedNumbers,
            statusCode: statusCode
        )
    }

    private func validateTrustedDevice2FACode(code: String, context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult {
        var verifyRequest = makeTwoFactorAuthRequest(url: Constants.URLs.grandSlamValidate, context: context)
        verifyRequest.setValue(code, forHTTPHeaderField: "security-code")

        if let allHeaders = verifyRequest.allHTTPHeaderFields {
            verboseLog("[SideSign] validateTrustedDevice2FACode HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        debugLog("[SideSign] Verifying trusted device security code...")
        let (verifyData, verifyHttpResponse) = try await performTwoFactorRequest(verifyRequest, actionName: "validate2FACode")
        let verifyStatusCode = verifyHttpResponse.safeStatusCode

        return try parseTwoFactorAuthVerifyResponse(data: verifyData, statusCode: verifyStatusCode, requirePeToken: false, httpResponse: verifyHttpResponse)
    }

    private func validatePhone2FACode(code: String,
                                      phoneID: String,
                                      mode: String,
                                      context: TwoFactorAuthContext) async throws -> TwoFactorAuthValidationResult
    {
        // SideInstaller: get_anisette_data again before verify (OTP expires ~60s)
        var ctx = context
        let refreshed = await Self.refreshOTPKeepingMachine(
            context.anisetteData,
            lockedCI: context.lockedClientInfo,
            lockedUA: context.lockedUserAgent
        )
        ctx = TwoFactorAuthContext(
            dsid: context.dsid,
            idmsToken: context.idmsToken,
            anisetteData: refreshed,
            xcodeVersion: context.xcodeVersion,
            lockedClientInfo: context.lockedClientInfo,
            lockedUserAgent: context.lockedUserAgent
        )

        // SideInstaller verify_sms_2fa — exact JSON POST
        let securityCodeURL = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode")!
        var verifyRequest = makeTwoFactorAuthRequest(url: securityCodeURL, context: ctx)
        verifyRequest.httpMethod = "POST"
        verifyRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        verifyRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        guard let phoneIdValue = Int(phoneID) else {
            throw DeveloperPortalError.invalidParameters(cause: "Unsupported phone id: \(phoneID)")
        }
        let jsonBody: [String: Any] = [
            "securityCode": ["code": code],
            "phoneNumber": ["id": phoneIdValue],
            "mode": mode
        ]
        verifyRequest.httpBody = try JSONSerialization.data(withJSONObject: jsonBody)

        if let allHeaders = verifyRequest.allHTTPHeaderFields {
            verboseLog("[SideSign] validatePhone2FACode HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        debugLog("[SideSign] Verifying phone security code (SideInstaller JSON)...")
        let (verifyData, verifyHttpResponse) = try await performTwoFactorRequest(verifyRequest, actionName: "validatePhone2FACode")
        let verifyStatusCode = verifyHttpResponse.safeStatusCode
        // SideInstaller: non-success → parse error; -21669 = wrong code → retry
        if verifyStatusCode == 503 || verifyStatusCode == 433 {
            var lastData = verifyData
            var lastStatus = verifyStatusCode
            var lastHttp = verifyHttpResponse
            for (i, delay) in [UInt64(2_000_000_000), UInt64(5_000_000_000), UInt64(10_000_000_000)].enumerated() {
                debugLog("[SideSign] Phone code submit HTTP \(lastStatus) — retry \(i + 1) after \(delay / 1_000_000_000)s")
                try await Task.sleep(nanoseconds: delay)
                let (retryData, retryHttp) = try await performTwoFactorRequest(verifyRequest, actionName: "validatePhone2FACode-retry")
                lastData = retryData
                lastStatus = retryHttp.safeStatusCode
                lastHttp = retryHttp
                if lastStatus != 503 && lastStatus != 433 { break }
            }
            // Last resort: same JSON body as Mac15,7 (SideInstaller MAC_CLIENT_INFO path)
            if lastStatus == 503 || lastStatus == 433 {
                debugLog("[SideSign] Phone code still HTTP \(lastStatus) — one attempt as MAC_CLIENT_INFO")
                var macReq = makeTwoFactorAuthRequest(url: securityCodeURL, context: ctx, asMac: true)
                macReq.httpMethod = "POST"
                macReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
                macReq.setValue("application/json", forHTTPHeaderField: "Accept")
                macReq.httpBody = verifyRequest.httpBody
                let (macData, macHttp) = try await performTwoFactorRequest(macReq, context: ctx, actionName: "validatePhone2FACode-mac")
                lastData = macData
                lastStatus = macHttp.safeStatusCode
                lastHttp = macHttp
            }
            return try parseTwoFactorAuthVerifyResponse(
                data: lastData,
                statusCode: lastStatus,
                requirePeToken: false,
                httpResponse: lastHttp
            )
        }

        // SideInstaller does not require X-Apple-PE-Token for phone verify success
        return try parseTwoFactorAuthVerifyResponse(
            data: verifyData,
            statusCode: verifyStatusCode,
            requirePeToken: false,
            httpResponse: verifyHttpResponse
        )
    }

    private func parseTwoFactorAuthVerifyResponse(data: Data,
                                                  statusCode: Int,
                                                  requirePeToken: Bool,
                                                  httpResponse: HTTPURLResponse?) throws -> TwoFactorAuthValidationResult
    {
        let verifyDictionary = parsePlistOrJSON(data)
        let (xmluiTitle, xmluiMessage) = parseXMLUIAlertMessage(from: data)
        let errorCode = verifyDictionary?["ec"] as? Int ?? 0
        let statusDict = verifyDictionary?["Status"] as? [String: any Sendable]
        let errorMsg = (verifyDictionary?["em"] as? String)
                    ?? (statusDict?["em"] as? String)
                    ?? xmluiMessage
                    ?? xmluiTitle

        if errorCode == GrandSlamAuthErrorCodes.tooManyAttempts
            || errorCode == GrandSlamAuthErrorCodes.tooManyCodesRequested
            || errorCode == GrandSlamAuthErrorCodes.rateLimited
            || statusCode == HTTPStatusCodes.tooManyRequests
        {
            let msg = errorMsg ?? "Too many verification code attempts. Please try again later."
            debugLog("[SideSign] Too many 2FA attempts (\(errorCode), HTTP \(statusCode)): \(msg)")
            throw DeveloperPortalError.tooManyAttempts(cause: msg)
        } else if errorCode == GrandSlamAuthErrorCodes.incorrectVerificationCode {
            let msg = errorMsg ?? "Incorrect verification code. Please try again."
            debugLog("[SideSign] Incorrect 2FA verification code (\(errorCode), HTTP \(statusCode)): \(msg)")
            return .retry(message: msg)
        } else if errorCode != 0 {
            let msg = errorMsg ?? "2FA verification error"
            debugLog("[SideSign] 2FA verification error (\(errorCode), HTTP \(statusCode)): \(msg)")
            if Self.isPhoneOrICloudRefuse(msg) {
                return .retry(message: "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices.")
            }
            throw ServerError.underlyingError(code: errorCode, message: Self.sanitize2FAUserMessage(msg))
        }

        if xmluiTitle != nil || xmluiMessage != nil {
            let message = xmluiMessage ?? errorMsg ?? xmluiTitle ?? "Verification failed"
            debugLog("[SideSign] 2FA verification fatal alert from Apple (HTTP \(statusCode)): \(message)")
            if Self.isPhoneOrICloudRefuse(message) {
                // Treat as wrong channel / refused phone — ask user to use device code
                return .retry(message: "Apple won't send a code by text or call to this sign-in, so it was sent to your Apple devices.")
            }
            throw DeveloperPortalError.invalid2FAResponse(cause: Self.sanitize2FAUserMessage(message))
        }

        if statusCode == 503 || statusCode == 433 {
            debugLog("[SideSign] 2FA verification HTTP \(statusCode) — treating as retryable")
            return .retry(message: "Apple temporarily refused the code (HTTP \(statusCode)). Wait a moment and try again, or use a code from your other Apple devices.")
        }

        guard statusCode == HTTPStatusCodes.ok else {
            let rawStr = prettyJSONString(from: data)
            let reason = errorMsg ?? HTTPStatusCodes.localizedDescription(for: statusCode)
            debugLog("[SideSign] 2FA verification failed (HTTP \(statusCode)): \(reason) - body: \(rawStr)")
            return .retry(message: reason)
        }

        if requirePeToken {
            guard httpResponse?.allHeaderFields.keys.contains(where: { ($0 as? String)?.lowercased() == "x-apple-pe-token" }) == true else {
                let rawStr = prettyJSONString(from: data)
                let reason = errorMsg ?? "Incorrect verification code or missing session token"
                debugLog("[SideSign] Secondary code verification failed (HTTP \(HTTPStatusCodes.ok) missing PE token header): \(reason) - Body: \(rawStr)")
                return .retry(message: reason)
            }
        }

        return .success
    }


    
    /// 认证相关请求统一走 DeveloperPortal 的 session；连接不复用由请求头
    /// `Connection: close` 控制，无需为每次请求新建 URLSession。


    private static func timestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date())
    }

    /// SideInstaller refreshes anisette before verify_sms and before login again (OTP ~60s).
    /// Same machine (adi / MD-M) when possible; new X-Apple-I-MD only.
    /// SideInstaller refreshes OTP via get_headers on the SAME adi.pb.
    /// Without adi.pb, only bump clientTime — never provision a new machine (that → HTTP 503 after SMS).
    private static func refreshOTPKeepingMachine(_ original: AnisetteData, lockedCI: String, lockedUA: String) async -> AnisetteData {
        AnisetteDataManager.shared.clearCache()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        func stamp(_ data: AnisetteData) -> AnisetteData {
            var copy = data
            copy.clientInfo = lockedCI
            copy.userAgent = lockedUA
            copy.clientTime = formatter.string(from: Date())
            return copy
        }

        // 机器身份由宿主注入的安全存储提供（Keychain 等），不读宿主 UserDefaults。
        let adiBlob = AnisetteDataManager.shared.identityStorage?.loadAdiBlob()

        // No saved identity → keep machine + OTP from password step (SideInstaller always has state)
        guard let adiBlob, !adiBlob.isEmpty else {
            debugLog("[SideSign] No stored adi.pb for OTP refresh — keeping same machine/OTP, new clientTime only")
            return stamp(original)
        }

        // 服务器模式由宿主通过 AnisetteDataManager.activeMode 配置，不再窥探宿主偏好项。
        guard let mode = AnisetteDataManager.shared.activeMode else {
            return stamp(original)
        }

        let identifier = UUID(uuidString: original.deviceID) ?? UUID()
        var requestHeaders = original.toRequestHeaders()
        requestHeaders.clientInfo = lockedCI
        requestHeaders.userAgent = lockedUA
        requestHeaders.clientTime = formatter.string(from: Date())

        do {
            let (fresh, newBlob) = try await AnisetteDataManager.shared.fetchAnisetteData(
                mode: mode,
                identifier: identifier,
                existingAdiBlob: adiBlob,
                headers: requestHeaders
            )
            if let newBlob {
                AnisetteDataManager.shared.identityStorage?.saveAdiBlob(newBlob)
            }
            // Accept full fresh headers for THIS adi only (SideInstaller get_headers)
            var result = stamp(fresh)
            // Hard-lock machine/device from the live session if server returns empty
            if result.machineID.isEmpty { result.machineID = original.machineID }
            if result.deviceID.isEmpty { result.deviceID = original.deviceID }
            if result.oneTimePassword.isEmpty { result.oneTimePassword = original.oneTimePassword }
            debugLog("[SideSign] OTP refreshed with existing adi.pb md-m=\(result.machineID.prefix(12))...")
            return result
        } catch {
            debugLog("[SideSign] OTP refresh failed (\(error)); same machine/OTP + new clientTime")
            return stamp(original)
        }
    }

    private func makeTwoFactorAuthRequest(url: URL, context: TwoFactorAuthContext) -> URLRequest {
        // SideInstaller build_2fa_headers + send_auth base_headers (minimal set).
        // Extra headers (Client-Time, Locale, SRL-NO, buddyml Accept, etc.) correlate with HTTP 503.
        let identityToken = "\(context.dsid):\(context.idmsToken)"
        let encodedIdentityToken = Data(identityToken.utf8).base64EncodedString()
        let a = context.anisetteData
        let clientInfo = context.lockedClientInfo
        let ua = context.lockedUserAgent

        var request = URLRequest(url: url)
        // Defaults match SideInstaller non-JSON auth pages; callers override for JSON phone.
        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "User-Agent": ua,
            "X-Mme-Client-Info": clientInfo,
            "X-Xcode-Version": "14.2 (14C18)",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Apple-Identity-Token": encodedIdentityToken,
            // SideInstaller get_headers: only these three anisette fields on 2FA pages
            "X-Mme-Device-Id": a.deviceID,
            "X-Apple-I-MD": a.oneTimePassword,
            "X-Apple-I-MD-M": a.machineID,
            "X-Apple-I-MD-RINFO": a.routingInfo,
            "Connection": "close",
        ]
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        return request
    }

    /// 身份已统一，不再做"切成另一台设备重试"的回退；只负责发出请求并保证拿到 HTTP 响应。
    private func performTwoFactorRequest(_ request: URLRequest, actionName: String) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw ServerError.badServerResponse(reason: "\(actionName) non-HTTP response", jsonPayload: body)
        }
        return (data, http)
    }

private func parsePlistOrJSON(_ data: Data) -> [String: any Sendable]? {
           (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: any Sendable]
        ?? (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: any Sendable]
    }
}
