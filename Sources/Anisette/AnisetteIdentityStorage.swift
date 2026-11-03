//
//  AnisetteIdentityStorage.swift
//  SideSign
//
//  宿主 App 提供的机器身份（adi.pb）存储抽象。
//  SideSign 不直接读写宿主的 UserDefaults / Keychain，由宿主注入实现。
//

import Foundation

/// 机器身份（adi.pb）的持久化接口。
///
/// 宿主应使用安全存储（如 Keychain）实现；SideSign 只通过该接口读写，
/// 避免把 adi.pb 明文写入 UserDefaults 或进入备份。
public protocol AnisetteIdentityStorage: Sendable {
    /// 读取已保存的 adi.pb；没有时返回 nil。
    func loadAdiBlob() -> Data?

    /// 保存最新的 adi.pb。
    func saveAdiBlob(_ blob: Data)
}
