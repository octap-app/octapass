// The desktop app's own strings: the quick-access window, and the vault window's additions to the web
// vault's screens (which use its catalog, `@octapass/web/src/i18n`). Same voice and format.

import { translator, type Translation } from '@octapass/web/src/i18n/core';

const en = {
  // Settings → Passkeys on Windows, the system passkey provider (`src-tauri/src/windows_passkey.rs`).
  passkeyProvider: {
    title: 'Passkeys in Windows',
    help: 'Let Windows and your browsers save and use passkeys from Octa Pass.',
    switch: 'Use Octa Pass as a passkey provider',
    switchHelp: 'Off by default, and only for this device. Each use asks for Windows Hello.',
    enable: 'Turn on Octa Pass in Windows Settings',
    enableHelp: 'One more step: Windows asks you to turn it on under Accounts → Passkeys → Advanced options.',
    openSettings: 'Open Windows Settings',
    enabled: 'Windows is using Octa Pass for passkeys.',
    failed: 'Windows didn’t accept the change. Try again.',
  },
  quick: {
    search: 'Search logins',
    results: 'Logins',
    empty: 'No logins yet.',
    noMatch: 'Nothing matches “{query}”.',
    // {what} is the field's label, like “Password”.
    copied: '{what} for {title} copied. The clipboard clears in {count} s.',
    nothingToCopy: '{title} has no {what} to copy.',
    // Lower case, for the middle of a sentence.
    fields: {
      username: 'username',
      password: 'password',
      code: 'one-time code',
    },
    keys: {
      password: 'password',
      username: 'username',
      code: 'code',
      type: 'type',
      close: 'close',
    },
    // Auto-type: typing a login into the window quick access was opened over.
    autoType: {
      action: 'Type into the window',
      typing: 'Typing {title}…',
      copied: 'Auto-type isn’t available here, so the password for {title} was copied. The clipboard clears in {count} s.',
      permission: 'To type, Octa Pass needs the Accessibility permission: System Settings → Privacy & Security → Accessibility.',
      openSettings: 'Open System Settings',
      screenLocked: 'The screen is locked, so nothing was typed.',
      noWindow: 'There’s no window to type into.',
      ownWindow: 'Octa Pass doesn’t type into its own windows.',
      focusChanged: '{window} took focus, so typing stopped.',
      noMatch: '{window} isn’t a window for {title}. Add its title to the login’s auto-type windows in Octa Pass.',
      keysHeld: 'Let go of the keys, then try again.',
      missingField: '{title} has no {what} to type.',
      invalidSequence: 'The auto-type sequence of {title} has a mistake. Fix it in Octa Pass.',
      failed: 'Couldn’t type. Try again.',
      into: 'Type into {window}',
      noLogin: 'No login is set up for {window}. Pick one, or add the window to a login’s auto-type windows.',
      pick: 'Pick a login to type.',
    },
    locked: 'Octa Pass is locked',
    signedOut: 'Sign in to Octa Pass first',
    unlockFailed: 'Not unlocked. Try again, or open Octa Pass and use your master password.',
    openApp: 'Open Octa Pass',
  },
};

const ar: Translation<typeof en> = {
  passkeyProvider: {
    title: 'مفاتيح المرور في Windows',
    help: 'اسمح لنظام Windows ومتصفحاتك بحفظ مفاتيح المرور واستخدامها من Octa Pass.',
    switch: 'استخدام Octa Pass موفِّرًا لمفاتيح المرور',
    switchHelp: 'معطَّل افتراضيًا، ولهذا الجهاز فقط. يطلب كل استخدام Windows Hello.',
    enable: 'شغِّل Octa Pass في إعدادات Windows',
    enableHelp: 'خطوة أخرى: يطلب منك Windows تشغيله من الحسابات ← مفاتيح المرور ← الخيارات المتقدمة.',
    openSettings: 'فتح إعدادات Windows',
    enabled: 'يستخدم Windows الآن Octa Pass لمفاتيح المرور.',
    failed: 'لم يقبل Windows التغيير. حاول مرة أخرى.',
  },
  quick: {
    search: 'البحث في بيانات الدخول',
    results: 'بيانات الدخول',
    empty: 'لا بيانات دخول بعد.',
    noMatch: 'لا شيء يطابق «{query}».',
    copied: {
      zero: 'تم نسخ {what} لـ {title}. تُمسح الحافظة الآن.',
      one: 'تم نسخ {what} لـ {title}. تُمسح الحافظة خلال ثانية واحدة.',
      two: 'تم نسخ {what} لـ {title}. تُمسح الحافظة خلال ثانيتين.',
      few: 'تم نسخ {what} لـ {title}. تُمسح الحافظة خلال {count} ثوانٍ.',
      many: 'تم نسخ {what} لـ {title}. تُمسح الحافظة خلال {count} ثانية.',
      other: 'تم نسخ {what} لـ {title}. تُمسح الحافظة خلال {count} ثانية.',
    },
    nothingToCopy: 'ليس في {title} {what} للنسخ.',
    fields: {
      username: 'اسم المستخدم',
      password: 'كلمة المرور',
      code: 'الرمز لمرة واحدة',
    },
    keys: {
      password: 'كلمة المرور',
      username: 'اسم المستخدم',
      code: 'الرمز',
      type: 'كتابة',
      close: 'إغلاق',
    },
    autoType: {
      action: 'الكتابة في النافذة',
      typing: 'تجري كتابة {title}…',
      copied: {
        zero: 'الكتابة التلقائية غير متاحة هنا، فنُسخت كلمة المرور لـ {title}. تُمسح الحافظة الآن.',
        one: 'الكتابة التلقائية غير متاحة هنا، فنُسخت كلمة المرور لـ {title}. تُمسح الحافظة خلال ثانية واحدة.',
        two: 'الكتابة التلقائية غير متاحة هنا، فنُسخت كلمة المرور لـ {title}. تُمسح الحافظة خلال ثانيتين.',
        few: 'الكتابة التلقائية غير متاحة هنا، فنُسخت كلمة المرور لـ {title}. تُمسح الحافظة خلال {count} ثوانٍ.',
        many: 'الكتابة التلقائية غير متاحة هنا، فنُسخت كلمة المرور لـ {title}. تُمسح الحافظة خلال {count} ثانية.',
        other: 'الكتابة التلقائية غير متاحة هنا، فنُسخت كلمة المرور لـ {title}. تُمسح الحافظة خلال {count} ثانية.',
      },
      permission: 'لكي يكتب Octa Pass يحتاج إلى إذن تسهيلات الاستخدام: إعدادات النظام ← الخصوصية والأمن ← تسهيلات الاستخدام.',
      openSettings: 'فتح إعدادات النظام',
      screenLocked: 'الشاشة مقفلة، فلم يُكتب شيء.',
      noWindow: 'لا نافذة للكتابة فيها.',
      ownWindow: 'لا يكتب Octa Pass في نوافذه.',
      focusChanged: 'انتقل التركيز إلى {window}، فتوقفت الكتابة.',
      noMatch: '{window} ليست نافذة لـ {title}. أضف عنوانها إلى نوافذ الكتابة التلقائية لبيانات الدخول في Octa Pass.',
      keysHeld: 'ارفع أصابعك عن المفاتيح، ثم حاول مرة أخرى.',
      missingField: 'ليس في {title} {what} للكتابة.',
      invalidSequence: 'في تسلسل الكتابة التلقائية لـ {title} خطأ. صحّحه في Octa Pass.',
      failed: 'تعذّرت الكتابة. حاول مرة أخرى.',
      into: 'الكتابة في {window}',
      noLogin: 'لا بيانات دخول مُعدّة لـ {window}. اختر واحدة، أو أضف النافذة إلى نوافذ الكتابة التلقائية لبيانات دخول.',
      pick: 'اختر بيانات الدخول لكتابتها.',
    },
    locked: 'Octa Pass مقفل',
    signedOut: 'سجّل الدخول إلى Octa Pass أولًا',
    unlockFailed: 'لم يُفتح القفل. حاول مرة أخرى، أو افتح Octa Pass واستخدم كلمة المرور الرئيسية.',
    openApp: 'فتح Octa Pass',
  },
};

export const catalogs = { en, ar };
export const td = translator<typeof en>(catalogs);
