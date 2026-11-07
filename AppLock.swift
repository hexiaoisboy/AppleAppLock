import SwiftUI
import AppKit
import Combine
import CryptoKit
import Security
import UniformTypeIdentifiers

// MARK: - Model

struct LockedApp: Codable, Identifiable, Equatable {
    let bundleID: String
    let name: String
    let path: String

    var id: String { bundleID }
}

private struct PendingUnlock {
    let bundleID: String
    let name: String
    let icon: NSImage?
    let bundleURL: URL?
}

enum RelockDelay: Int, CaseIterable, Identifiable {
    case immediate = 0
    case twoMinutes = 120
    case fiveMinutes = 300

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .immediate: return "立即生效"
        case .twoMinutes: return "2 分钟"
        case .fiveMinutes: return "5 分钟"
        }
    }

    var interval: TimeInterval { TimeInterval(rawValue) }
}

// MARK: - Paths

enum AppPaths {
    static var supportDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AppLock", isDirectory: true)
    }

    static var passwordFile: URL { supportDirectory.appendingPathComponent("password.bin") }
    static var appsFile: URL { supportDirectory.appendingPathComponent("apps.json") }

    static func prepare() {
        try? FileManager.default.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
    }
}

// MARK: - Password

enum PasswordStore {
    private static let iterations = 60_000
    private static let saltLength = 16
    private static let digestLength = 32

    static var hasPassword: Bool {
        guard let data = try? Data(contentsOf: AppPaths.passwordFile) else { return false }
        return data.count == saltLength + digestLength
    }

    static func setPassword(_ password: String) throws {
        AppPaths.prepare()
        var salt = Data(count: saltLength)
        let status = salt.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, saltLength, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw NSError(domain: "AppLock", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "无法生成随机盐。"])
        }

        var payload = salt
        payload.append(hash(password: password, salt: salt))
        try payload.write(to: AppPaths.passwordFile, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                               ofItemAtPath: AppPaths.passwordFile.path)
    }

    static func verify(_ password: String) -> Bool {
        guard let data = try? Data(contentsOf: AppPaths.passwordFile),
              data.count == saltLength + digestLength else { return false }
        let salt = data.prefix(saltLength)
        let expected = [UInt8](data.suffix(digestLength))
        let actual = [UInt8](hash(password: password, salt: Data(salt)))
        guard expected.count == actual.count else { return false }

        var difference: UInt8 = 0
        for index in expected.indices {
            difference |= expected[index] ^ actual[index]
        }
        return difference == 0
    }

    private static func hash(password: String, salt: Data) -> Data {
        var input = salt
        input.append(contentsOf: Array(password.utf8))
        var current = Data(SHA256.hash(data: input))
        for _ in 1..<iterations {
            var round = salt
            round.append(current)
            current = Data(SHA256.hash(data: round))
        }
        return current
    }
}

// MARK: - Launch at login

enum LaunchAtLogin {
    private static let label = "com.hexiao.AppLock"

    private static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static var isEnabled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    static func set(_ enabled: Bool) {
        if enabled {
            install()
        } else {
            uninstall()
        }
    }

    private static func install() {
        let appPath = Bundle.main.bundlePath
        guard appPath.hasSuffix(".app") else { return }

        try? FileManager.default.createDirectory(at: plistURL.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": ["/usr/bin/open", "-a", appPath],
            "RunAtLoad": true,
        ]
        guard let data = try? PropertyListSerialization.data(fromPropertyList: plist,
                                                            format: .xml,
                                                            options: 0) else { return }
        try? data.write(to: plistURL, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o644],
                                               ofItemAtPath: plistURL.path)

        let domain = "gui/\(getuid())"
        run("/bin/launchctl", ["bootout", domain, plistURL.path])
        run("/bin/launchctl", ["bootstrap", domain, plistURL.path])
    }

    private static func uninstall() {
        let domain = "gui/\(getuid())"
        run("/bin/launchctl", ["bootout", domain, plistURL.path])
        try? FileManager.default.removeItem(at: plistURL)
    }

    private static func run(_ executable: String, _ arguments: [String]) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }
}

// MARK: - Password prompt

@MainActor
enum PasswordPrompt {
    static func ask(title: String, message: String, icon: NSImage? = nil) -> String? {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = message
        if let icon { alert.icon = icon }
        alert.addButton(withTitle: "解锁")
        alert.addButton(withTitle: "取消")

        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.placeholderString = "密码"
        alert.accessoryView = field
        alert.window.level = .floating
        alert.window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        alert.window.initialFirstResponder = field

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return field.stringValue
    }

    static func askNew(title: String = "设置密码") -> String? {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = title
        alert.informativeText = "密码至少 4 位。"
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "取消")

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 280, height: 58))
        let first = NSSecureTextField(frame: NSRect(x: 0, y: 32, width: 280, height: 24))
        first.placeholderString = "新密码"
        let second = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        second.placeholderString = "再次输入新密码"
        container.addSubview(first)
        container.addSubview(second)
        alert.accessoryView = container
        alert.window.level = .floating
        alert.window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        alert.window.initialFirstResponder = first

        while true {
            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            let password = first.stringValue
            if password.count < 4 {
                NSSound.beep()
                alert.informativeText = "密码至少 4 位。"
                first.stringValue = ""
                second.stringValue = ""
                alert.window.makeFirstResponder(first)
                continue
            }
            if password != second.stringValue {
                NSSound.beep()
                alert.informativeText = "两次输入不一致，请重试。"
                second.stringValue = ""
                alert.window.makeFirstResponder(second)
                continue
            }
            return password
        }
    }

    static func showMessage(title: String, message: String, style: NSAlert.Style = .warning) {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = style
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "好")
        alert.window.level = .floating
        alert.window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        alert.runModal()
    }
}

// MARK: - Launch watcher

private final class LaunchWatcher: NSObject {
    var onLaunch: (@MainActor (NSRunningApplication) -> Void)?
    var onTerminate: (@MainActor (NSRunningApplication) -> Void)?

    func start() {
        let center = NSWorkspace.shared.notificationCenter
        center.addObserver(self, selector: #selector(applicationDidLaunch(_:)),
                           name: NSWorkspace.didLaunchApplicationNotification, object: nil)
        center.addObserver(self, selector: #selector(applicationDidTerminate(_:)),
                           name: NSWorkspace.didTerminateApplicationNotification, object: nil)
    }

    @objc private func applicationDidLaunch(_ notification: Notification) {
        deliver(notification, to: onLaunch)
    }

    @objc private func applicationDidTerminate(_ notification: Notification) {
        deliver(notification, to: onTerminate)
    }

    private func deliver(_ notification: Notification,
                         to handler: (@MainActor (NSRunningApplication) -> Void)?) {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
              let handler else { return }
        if Thread.isMainThread {
            MainActor.assumeIsolated { handler(app) }
        } else {
            DispatchQueue.main.async {
                MainActor.assumeIsolated { handler(app) }
            }
        }
    }
}

// MARK: - Manager

@MainActor
final class LockManager: ObservableObject {
    static let shared = LockManager()

    @Published private(set) var lockedApps: [LockedApp] = []
    @Published private(set) var hasPassword = false
    @Published private(set) var isEnabled = true
    @Published private(set) var launchAtLogin = false
    @Published private(set) var relockDelay: RelockDelay = .immediate

    private let defaults = UserDefaults.standard
    private let watcher = LaunchWatcher()
    private var pending: [PendingUnlock] = []
    private var unlockedUntil: [String: Date] = [:]
    private var suppressUntil: [String: Date] = [:]
    private var ignoredTerminationPIDs: [pid_t: Date] = [:]
    private var isPrompting = false

    private static let blockedBundleIDs: Set<String> = [
        "com.apple.finder",
        "com.apple.dock",
        "com.apple.loginwindow",
        "com.apple.SystemUIServer",
        "com.apple.WindowManager",
        "com.apple.controlcenter",
        "com.apple.notificationcenterui",
        "com.apple.Spotlight",
    ]

    var canLock: Bool { hasPassword && isEnabled }

    private init() {
        hasPassword = PasswordStore.hasPassword
        loadApps()
        isEnabled = defaults.object(forKey: "enabled") as? Bool ?? true
        launchAtLogin = LaunchAtLogin.isEnabled
        if let raw = defaults.object(forKey: "relockDelay") as? Int,
           let delay = RelockDelay(rawValue: raw) {
            relockDelay = delay
        }
        watcher.onLaunch = { [weak self] app in
            self?.evaluate(app)
        }
        watcher.onTerminate = { [weak self] app in
            self?.handleTermination(app)
        }
        watcher.start()
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 600_000_000)
            self.scanRunningApps()
        }
    }

    // MARK: List

    func add(url: URL) {
        guard let bundle = Bundle(url: url) else {
            PasswordPrompt.showMessage(title: "无法添加", message: "这不是一个可识别的应用程序。")
            return
        }
        guard let bundleID = bundle.bundleIdentifier else {
            PasswordPrompt.showMessage(title: "无法添加", message: "该程序没有内置标识，无法锁定。")
            return
        }
        guard bundleID != Bundle.main.bundleIdentifier else { return }
        guard !Self.blockedBundleIDs.contains(bundleID) else {
            PasswordPrompt.showMessage(title: "无法锁定", message: "系统关键程序不能锁定。")
            return
        }
        guard !lockedApps.contains(where: { $0.bundleID == bundleID }) else { return }

        let name = (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? url.deletingPathExtension().lastPathComponent
        lockedApps.append(LockedApp(bundleID: bundleID, name: name, path: url.path))
        saveApps()

        guard let running = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
            .first(where: { !$0.isTerminated }) else { return }
        NSApp.activate()
        let alert = NSAlert()
        alert.messageText = "\(name) 正在运行"
        alert.informativeText = "要立即关闭它吗？"
        alert.addButton(withTitle: "关闭")
        alert.addButton(withTitle: "稍后")
        alert.window.level = .floating
        alert.window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        if alert.runModal() == .alertFirstButtonReturn {
            close(running)
        }
    }

    func remove(_ app: LockedApp) {
        if canLock && !requirePassword("需要密码才能移除已锁定的程序。") { return }
        lockedApps.removeAll { $0.bundleID == app.bundleID }
        unlockedUntil[app.bundleID] = nil
        saveApps()
    }

    // MARK: Password

    func setInitialPassword() {
        guard !hasPassword else { return }
        guard let password = PasswordPrompt.askNew(title: "设置密码") else { return }
        do {
            try PasswordStore.setPassword(password)
            hasPassword = true
            isEnabled = true
            defaults.set(true, forKey: "enabled")
            scanRunningApps()
        } catch {
            PasswordPrompt.showMessage(title: "保存失败", message: error.localizedDescription)
        }
    }

    func changePassword() {
        guard hasPassword else {
            setInitialPassword()
            return
        }
        guard let current = PasswordPrompt.ask(title: "修改密码", message: "请输入当前密码。") else { return }
        guard PasswordStore.verify(current) else {
            PasswordPrompt.showMessage(title: "密码错误", message: "当前密码不正确。")
            return
        }
        guard let fresh = PasswordPrompt.askNew(title: "设置新密码") else { return }
        do {
            try PasswordStore.setPassword(fresh)
            hasPassword = true
        } catch {
            PasswordPrompt.showMessage(title: "保存失败", message: error.localizedDescription)
        }
    }

    func requirePassword(_ reason: String) -> Bool {
        guard hasPassword else { return true }
        guard let password = PasswordPrompt.ask(title: "需要密码", message: reason) else { return false }
        if PasswordStore.verify(password) { return true }
        NSSound.beep()
        PasswordPrompt.showMessage(title: "密码错误", message: "操作已取消。")
        return false
    }

    // MARK: Settings

    func requestToggleEnabled(_ enabled: Bool) {
        if enabled {
            guard hasPassword else {
                PasswordPrompt.showMessage(title: "请先设置密码", message: "设置密码后才能启用锁定。")
                return
            }
            isEnabled = true
            defaults.set(true, forKey: "enabled")
            scanRunningApps()
        } else {
            guard requirePassword("需要密码才能关闭锁定。") else { return }
            isEnabled = false
            defaults.set(false, forKey: "enabled")
        }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        LaunchAtLogin.set(enabled)
        launchAtLogin = LaunchAtLogin.isEnabled
        if launchAtLogin != enabled {
            PasswordPrompt.showMessage(title: "设置失败",
                                       message: "无法写入登录启动项。请把程序放在固定位置后重试。")
        }
    }

    func setRelockDelay(_ delay: RelockDelay) {
        relockDelay = delay
        defaults.set(delay.rawValue, forKey: "relockDelay")
    }

    func requestQuit() {
        if canLock && !requirePassword("需要密码才能退出程序锁。") { return }
        NSApp.terminate(nil)
    }

    // MARK: Enforcement

    private func evaluate(_ app: NSRunningApplication) {
        guard canLock, !app.isTerminated, let bundleID = app.bundleIdentifier else { return }
        guard bundleID != Bundle.main.bundleIdentifier else { return }
        guard let locked = lockedApps.first(where: { $0.bundleID == bundleID }) else { return }

        if let until = unlockedUntil[bundleID], until > Date() { return }
        if let until = suppressUntil[bundleID], until > Date() {
            app.forceTerminate()
            return
        }
        guard !pending.contains(where: { $0.bundleID == bundleID }) else { return }

        // 先关闭再询问密码：密码框挡不住另一个程序的键盘和鼠标
        let item = PendingUnlock(
            bundleID: bundleID,
            name: locked.name,
            icon: app.icon,
            bundleURL: app.bundleURL
                ?? NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        )
        suppressUntil[bundleID] = Date().addingTimeInterval(1.5)
        close(app)
        pending.append(item)
        pump()
    }

    private func pump() {
        guard !isPrompting, !pending.isEmpty, canLock else { return }
        let item = pending.removeFirst()
        if let until = unlockedUntil[item.bundleID], until > Date() {
            pump()
            return
        }

        isPrompting = true
        Task { @MainActor in
            // 等关闭动作完成，避免密码框出现时程序仍在运行
            try? await Task.sleep(nanoseconds: 400_000_000)
            guard self.canLock else {
                self.isPrompting = false
                self.pump()
                return
            }

            let password = PasswordPrompt.ask(
                title: "解锁 \(item.name)",
                message: "「\(item.name)」已关闭。输入密码后重新打开；取消则保持关闭。",
                icon: item.icon
            )
            self.isPrompting = false

            if let password, PasswordStore.verify(password) {
                // 运行期间保持解锁，退出时再按「退出后锁定」设置计算期限
                self.unlockedUntil[item.bundleID] = .distantFuture
                if let url = item.bundleURL {
                    self.reopen(url)
                }
            }
            self.pump()
        }
    }

    private func close(_ app: NSRunningApplication) {
        guard !app.isTerminated else { return }
        ignoredTerminationPIDs = ignoredTerminationPIDs.filter { $0.value > Date() }
        ignoredTerminationPIDs[app.processIdentifier] = Date().addingTimeInterval(5)
        app.terminate()
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 250_000_000)
            if !app.isTerminated {
                app.forceTerminate()
            }
        }
    }

    private func handleTermination(_ app: NSRunningApplication) {
        let pid = app.processIdentifier
        if let ignoredUntil = ignoredTerminationPIDs.removeValue(forKey: pid),
           ignoredUntil > Date() {
            return
        }
        guard let bundleID = app.bundleIdentifier,
              let until = unlockedUntil[bundleID], until > Date() else { return }

        if relockDelay == .immediate {
            unlockedUntil[bundleID] = nil
        } else {
            unlockedUntil[bundleID] = Date().addingTimeInterval(relockDelay.interval)
        }
    }

    private func reopen(_ url: URL) {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, error in
            guard let error else { return }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    PasswordPrompt.showMessage(title: "无法重新打开程序",
                                               message: error.localizedDescription)
                }
            }
        }
    }

    private func scanRunningApps() {
        guard canLock else { return }
        for locked in lockedApps {
            let running = NSRunningApplication.runningApplications(withBundleIdentifier: locked.bundleID)
            for app in running where !app.isTerminated {
                evaluate(app)
            }
        }
    }

    // MARK: Persistence

    private func loadApps() {
        guard let data = try? Data(contentsOf: AppPaths.appsFile),
              let apps = try? JSONDecoder().decode([LockedApp].self, from: data) else { return }
        lockedApps = apps
    }

    private func saveApps() {
        AppPaths.prepare()
        guard let data = try? JSONEncoder().encode(lockedApps) else { return }
        try? data.write(to: AppPaths.appsFile, options: [.atomic])
    }
}

// MARK: - UI

struct ContentView: View {
    @EnvironmentObject private var manager: LockManager

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if !manager.hasPassword {
                passwordBanner
            }
            Divider()
            appSection
            Divider()
            HStack(spacing: 8) {
                Button {
                    addApp()
                } label: {
                    Label("添加程序", systemImage: "plus")
                }
                Spacer()
                Button("修改密码") { manager.changePassword() }
            }
            Toggle("开机时自动启动", isOn: Binding(
                get: { manager.launchAtLogin },
                set: { manager.setLaunchAtLogin($0) }
            ))
            .toggleStyle(.switch)
            VStack(alignment: .leading, spacing: 4) {
                Text("退出后锁定")
                    .font(.callout)
                Picker("退出后锁定", selection: Binding(
                    get: { manager.relockDelay },
                    set: { manager.setRelockDelay($0) }
                )) {
                    ForEach(RelockDelay.allCases) { delay in
                        Text(delay.title).tag(delay)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
            }
            HStack {
                Toggle("启用锁定", isOn: Binding(
                    get: { manager.isEnabled },
                    set: { manager.requestToggleEnabled($0) }
                ))
                .toggleStyle(.switch)
                Spacer()
                Button("退出") { manager.requestQuit() }
            }
        }
        .padding(14)
        .frame(width: 330)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: manager.canLock ? "lock.shield.fill" : "lock.shield")
                .font(.title2)
                .foregroundStyle(manager.canLock ? Color.accentColor : Color.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("程序锁")
                    .font(.headline)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var statusText: String {
        if !manager.hasPassword { return "先设置一个密码" }
        if !manager.isEnabled { return "锁定已暂停" }
        if manager.lockedApps.isEmpty { return "尚未添加程序" }
        return "已保护 \(manager.lockedApps.count) 个程序"
    }

    private var passwordBanner: some View {
        HStack {
            Text("尚未设置密码")
                .font(.callout)
            Spacer()
            Button("设置密码") { manager.setInitialPassword() }
        }
        .padding(10)
        .background(Color.yellow.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))
    }

    private var appSection: some View {
        Group {
            if manager.lockedApps.isEmpty {
                Text("还没有添加要锁定的程序")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 54)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Text("已锁定程序")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ScrollView {
                        LazyVStack(spacing: 4) {
                            ForEach(manager.lockedApps) { app in
                                row(app)
                            }
                        }
                    }
                    // 菜单栏弹窗按内容自适应高度，ScrollView 不给明确高度会被压扁
                    .frame(height: min(CGFloat(manager.lockedApps.count) * 24 + 8, 200))
                }
            }
        }
    }

    private func row(_ app: LockedApp) -> some View {
        HStack(spacing: 8) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                .resizable()
                .frame(width: 20, height: 20)
            Text(app.name)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 8)
            Button {
                manager.remove(app)
            } label: {
                Image(systemName: "trash")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .help("移除")
        }
        .padding(.vertical, 2)
    }

    private func addApp() {
        NSApp.activate()
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.prompt = "锁定"
        panel.message = "选择要锁定的程序"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        manager.add(url: url)
    }
}

@main
@MainActor
struct AppLockApp: App {
    @StateObject private var manager = LockManager.shared

    var body: some Scene {
        MenuBarExtra {
            ContentView()
                .environmentObject(manager)
        } label: {
            Image(systemName: manager.canLock ? "lock.fill" : "lock.open")
        }
        .menuBarExtraStyle(.window)
    }
}
