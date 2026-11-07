import OctaPassResources
import OctaPassVault
import SwiftUI
#if os(iOS)
import UIKit

@main
struct OctaPassApp: App {
    @State private var model = AppModel.live()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                // Every screen reads its strings again when the language changes.
                .id(model.languageVersion)
                .environment(\.layoutDirection, model.layoutDirection)
                .environment(\.locale, model.locale)
                .modifier(ThemeModifier(scheme: model.colorScheme))
                .modifier(ToastOverlay(toast: $model.toast))
                .background(ActivityTracker { model.recordActivity() })
                // The app switcher's snapshot shows the logo, never the vault.
                .overlay { if scenePhase != .active { PrivacyCover() } }
                .onOpenURL { url in
                    if OpenedLinks.accepts(url) { model.openedLinks.append(url.absoluteString) }
                }
                .onContinueUserActivity(CredentialExchange.activityType) { activity in
                    if let token = CredentialExchange.token(activity) { model.received.append(.token(token)) }
                }
        }
        .onChange(of: scenePhase) { _, phase in model.scenePhaseChanged(phase) }
    }
}
#endif

/// Signed out: sign in, create an account or a local vault. Locked: unlock. Otherwise the vault.
struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        ZStack {
            Group {
                if model.accountDeleted {
                    AuthLayout(title: L10n.deleted.title, subtitle: L10n.deleted.subtitle) {
                        PrimaryButton(title: L10n.deleted.backToStart) { model.accountDeleted = false }
                    }
                } else if model.session.status == .signedOut || model.signingUp {
                    OnboardingView()
                } else if model.session.status == .locked {
                    // Each local vault starts its lock screen over: its unlock methods, what's typed.
                    UnlockView().id(model.currentLocalVault?.tag)
                } else {
                    MainView()
                        .sheet(isPresented: Binding(
                            get: { model.offerDeviceUnlock != nil },
                            set: { if !$0 { model.offerDeviceUnlock = nil } }
                        )) {
                            DeviceUnlockOffer(label: model.offerDeviceUnlock ?? "")
                                .presentationDetents([.medium])
                        }
                }
            }
            // Above the session's screens by hand, not in a sheet: a finished reset signs in and
            // swaps the screens underneath, and the new Recovery Kit still has to be shown.
            if model.resettingPassword {
                PasswordResetView()
                    .transition(.move(edge: .bottom))
                    .zIndex(1)
            }
            // Over the vault's screens, by hand for the same reason: nothing may swipe it away,
            // and while the vault is locked it waits behind the lock screen.
            if let pending = model.newKit, model.session.status == .unlocked {
                NewRecoveryKitView(pending: pending)
                    .transition(.move(edge: .bottom))
                    .zIndex(1)
            }
            if model.turningOnSync {
                TurnOnSyncView()
                    .transition(.move(edge: .bottom))
                    .zIndex(1)
            }
        }
        .animation(.default, value: model.session.status)
        .animation(.default, value: model.resettingPassword)
        .animation(.default, value: model.newKit == nil)
        .animation(.default, value: model.turningOnSync)
    }
}

/// Sign in, Create account, or a vault on this phone only. They swap in place, so the sign-up
/// form and a new local vault's steps stay while the session changes around them.
struct OnboardingView: View {
    @State private var screen = Screen.signIn

    enum Screen { case signIn, signUp, createLocal, restore }

    var body: some View {
        Group {
            switch screen {
            case .signIn:
                SignInView(
                    onCreateAccount: { go(.signUp) }, onCreateLocal: { go(.createLocal) }, onRestore: { go(.restore) })
                    .transition(.move(edge: .leading))
            case .signUp:
                SignUpView { go(.signIn) }
                    .transition(.move(edge: .trailing))
            case .createLocal:
                CreateLocalView { go(.signIn) }
                    .transition(.move(edge: .trailing))
            case .restore:
                RestoreBackupView { go(.signIn) }
                    .transition(.move(edge: .trailing))
            }
        }
    }

    private func go(_ next: Screen) {
        withAnimation { screen = next }
    }
}

/// What the app switcher shows instead of the screen.
struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThickMaterial)
            Image("LogoTile").resizable().frame(width: 72, height: 72)
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

#if os(iOS)
/// Every touch counts as activity, so auto-lock waits for the user to stop (plan 03). A gesture
/// recogniser on the window that never takes a touch for itself. The Mac app has its own, for the
/// keyboard and the mouse.
struct ActivityTracker: UIViewRepresentable {
    let onActivity: () -> Void

    func makeUIView(context: Context) -> UIView {
        let view = TrackerView()
        view.onActivity = onActivity
        view.isUserInteractionEnabled = false
        return view
    }

    func updateUIView(_ view: UIView, context: Context) {
        (view as? TrackerView)?.onActivity = onActivity
    }

    final class TrackerView: UIView, UIGestureRecognizerDelegate {
        var onActivity: () -> Void = {}
        private var recognizer: UIGestureRecognizer?

        override func didMoveToWindow() {
            super.didMoveToWindow()
            guard let window, recognizer == nil else { return }
            let recognizer = TouchRecognizer { [weak self] in self?.onActivity() }
            recognizer.cancelsTouchesInView = false
            recognizer.delaysTouchesBegan = false
            recognizer.delegate = self
            window.addGestureRecognizer(recognizer)
            self.recognizer = recognizer
        }

        func gestureRecognizer(_ gesture: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
            true
        }
    }

    final class TouchRecognizer: UIGestureRecognizer {
        let onTouch: () -> Void

        init(onTouch: @escaping () -> Void) {
            self.onTouch = onTouch
            super.init(target: nil, action: nil)
        }

        override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
            onTouch()
            state = .failed
        }
    }
}
#endif
