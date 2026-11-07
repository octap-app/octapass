import { normalize } from '../dom/text';

// Keywords in English plus the ten most spoken languages on the web: Chinese, Spanish, Hindi, Arabic,
// Portuguese, French, Russian, Japanese, German (and Italian / Turkish where it's free).
// Written naturally; `normalize()` folds accents and Arabic variants on both sides.
const TEXT = {
  username: [
    'username', 'user name', 'user id', 'userid', 'login id', 'login name', 'sign-in name', 'account name',
    'account id', 'member id', 'customer id', 'email or phone', 'email or username', 'phone or email',
    'usuario', 'nombre de usuario', 'identifiant', "nom d'utilisateur", 'utilisateur', 'benutzername',
    'benutzer', 'anmeldename', 'nome de usuario', 'utilizador', 'utente', 'nome utente', 'kullanici adi',
    'имя пользователя', 'логин', 'пользователь', '用户名', '用戶名', '账号', '帳號', '账户', '登录名', '登录账号',
    'ユーザー名', 'ユーザ名', 'ユーザーid', 'ログインid', 'アカウント', 'اسم المستخدم', 'المستخدم', 'الحساب',
    'उपयोगकर्ता नाम', 'यूज़रनेम', 'उपयोगकर्ता', 'लॉगिन आईडी',
  ],
  email: [
    'email', 'e-mail', 'email address', 'e-mail address', 'mail address', 'correo', 'correo electronico', 'courriel', 'adresse e-mail', 'adresse mail',
    'e-mail-adresse', 'endereco de e-mail', 'электронная почта', 'эл. почта', 'почта', 'email адрес', '邮箱',
    '电子邮件', '電子郵件', '邮件地址', 'メールアドレス', 'メール', 'البريد الالكتروني', 'البريد', 'ईमेल', 'ई-मेल',
  ],
  password: [
    'password', 'passwort', 'passcode', 'passphrase', 'contrasena', 'clave', 'mot de passe', 'kennwort', 'senha',
    'palavra-passe', 'parola', 'sifre', 'пароль', '密码', '密碼', 'パスワード', 'كلمة المرور', 'كلمة السر',
    'كلمه المرور', 'كلمه السر', 'पासवर्ड', 'कूटशब्द',
  ],
  new: [
    'new', 'create', 'choose', 'set a', 'set your', 'nueva', 'nuevo', 'crea', 'elige', 'nouveau', 'nouvelle', 'creer',
    'choisissez', 'neues', 'neue', 'erstellen', 'festlegen', 'nova', 'novo', 'crie', 'escolha', 'nuova',
    'новый', 'придумайте', 'создайте', '新密码', '新密碼', '设置密码', '新しい', 'الجديده', 'جديده', 'انشاء', 'नया', 'नई',
  ],
  confirm: [
    'confirm', 'repeat', 'retype', 're-type', 're-enter', 'reenter', 'again', 'verify', 'confirmar', 'confirma',
    'repite', 'repetir', 'confirmer', 'confirmation', 'retapez', 'repeter', 'bestatigen', 'bestatigung', 'wiederholen',
    'confirme', 'repita', 'conferma', 'ripeti', 'tekrar', 'подтвердите', 'подтверждение', 'повторите', 'еще раз',
    '确认', '確認', '再次', '重复', '再入力', 'もう一度', 'تاكيد', 'اعد', 'اعاده', 'पुष्टि', 'दोबारा', 'फिर से',
  ],
  current: [
    'current', 'old', 'existing', 'previous', 'actual', 'anterior', 'actuel', 'ancien', 'aktuelles', 'aktuell',
    'altes', 'bisheriges', 'atual', 'antiga', 'attuale', 'vecchia', 'mevcut', 'текущий', 'старый', 'нынешний',
    '当前', '旧密码', '原密码', '目前', '現在の', '古い', 'الحاليه', 'القديمه', 'वर्तमान', 'पुराना',
  ],
  'one-time-code': [
    'one-time code', 'one time code', 'one-time password', 'verification code', 'authentication code',
    'security code', '2fa', 'two-factor', 'two factor', 'otp', 'totp', 'mfa', 'auth code', 'sms code',
    'authenticator', '6-digit', '6 digit', 'enter the code', 'enter code', 'codigo de verificacion',
    'codigo de seguridad', 'code de verification', 'code a usage unique', 'bestatigungscode', 'verifizierungscode',
    'sicherheitscode', 'einmalcode', 'codigo de verificacao', 'codice di verifica', 'dogrulama kodu',
    'код подтверждения', 'одноразовый код', 'код из смс', 'проверочный код', '验证码', '驗證碼', '动态码', '確認コード',
    '認証コード', 'ワンタイム', 'رمز التحقق', 'رمز التاكيد', 'رمز التفعيل', 'सत्यापन कोड', 'ओटीपी',
  ],
  'cc-number': [
    'card number', 'credit card', 'debit card', 'card no', 'cc number', 'numero de tarjeta', 'numero de la tarjeta',
    'numero de carte', 'kartennummer', 'numero do cartao', 'numero della carta', 'kart numarasi', 'номер карты',
    '卡号', '卡號', '信用卡号', 'カード番号', 'رقم البطاقه', 'कार्ड नंबर', 'कार्ड संख्या',
  ],
  'cc-name': [
    'name on card', 'cardholder', 'card holder', 'name on the card', 'nombre en la tarjeta', 'titular',
    'nom du titulaire', 'titulaire', 'karteninhaber', 'nome no cartao', 'intestatario', 'kart sahibi',
    'имя владельца', 'владелец карты', '持卡人', 'カード名義', 'اسم حامل البطاقه', 'الاسم على البطاقه',
    'कार्डधारक',
  ],
  'cc-exp': [
    'expiry', 'expiration', 'exp date', 'expires', 'valid thru', 'valid through', 'mm/yy', 'mm / yy', 'mm/yyyy',
    'vencimiento', 'caducidad', "date d'expiration", 'ablaufdatum', 'gultig bis', 'validade', 'scadenza',
    'son kullanma', 'срок действия', '有效期', '有効期限', 'تاريخ الانتهاء', 'समाप्ति',
  ],
  'cc-csc': [
    'cvv', 'cvc', 'csc', 'cvn', 'cvv2', 'card verification', 'security code', 'codigo de seguridad', 'cryptogramme',
    'prufnummer', 'codigo de seguranca', 'codice di sicurezza', 'код cvv', '安全码', 'セキュリティコード', 'رمز الامان',
    'सीवीवी',
  ],
  month: ['month', 'mes', 'mois', 'monat', 'mese', 'месяц', '月', 'الشهر', 'महीना'],
  year: ['year', 'ano', 'annee', 'jahr', 'anno', 'год', '年', 'السنه', 'वर्ष'],
  'given-name': [
    'first name', 'given name', 'forename', 'nombre', 'prenom', 'vorname', 'primeiro nome', 'nome proprio',
    'ad', 'имя', '名字', 'ファーストネーム', 'الاسم الاول', 'पहला नाम',
  ],
  'family-name': [
    'last name', 'surname', 'family name', 'apellido', 'apellidos', 'nom de famille', 'nom', 'nachname', 'sobrenome',
    'cognome', 'soyad', 'soyadi', 'фамилия', '姓氏', '苗字', 'ラストネーム', 'اسم العائله', 'الكنيه', 'उपनाम', 'अंतिम नाम',
  ],
  name: [
    'full name', 'your name', 'name', 'nombre completo', 'nom complet', 'vollstandiger name', 'nome completo',
    'полное имя', 'фио', '姓名', '氏名', 'お名前', 'الاسم الكامل', 'الاسم', 'पूरा नाम', 'नाम',
  ],
  tel: [
    'phone', 'mobile', 'telephone', 'cell', 'telefono', 'movil', 'portable', 'telefon', 'handy', 'telefone',
    'celular', 'cellulare', 'телефон', '电话', '電話', '手机', '携帯', 'رقم الهاتف', 'الهاتف', 'الجوال', 'فون',
    'फ़ोन', 'फोन', 'मोबाइल',
  ],
  organization: [
    'company', 'organization', 'organisation', 'business name', 'empresa', 'societe', 'entreprise', 'firma',
    'unternehmen', 'azienda', 'sirket', 'компания', 'организация', '公司', '会社', 'الشركه', 'कंपनी',
  ],
  'address-line2': [
    'address line 2', 'address 2', 'apartment', 'apt', 'suite', 'unit', 'building', 'floor', 'depto',
    'departamento', 'complement', 'adresszusatz', 'complemento', 'interno', 'квартира', '建物', 'شقه', 'फ्लैट',
  ],
  'address-line1': [
    'address', 'street', 'address line 1', 'direccion', 'calle', 'adresse', 'strasse', 'endereco', 'rua',
    'indirizzo', 'adres', 'адрес', 'улица', '地址', '住所', '番地', 'العنوان', 'الشارع', 'पता',
  ],
  'address-level2': [
    'city', 'town', 'ciudad', 'ville', 'stadt', 'ort', 'cidade', 'citta', 'sehir', 'город', '城市', '市区町村',
    'المدينه', 'शहर',
  ],
  'address-level1': [
    'state', 'province', 'region', 'county', 'estado', 'provincia', 'bundesland', 'regiao', 'область',
    'регион', '省', '都道府県', 'المنطقه', 'الولايه', 'المحافظه', 'राज्य',
  ],
  'postal-code': [
    'zip', 'postal code', 'postcode', 'post code', 'codigo postal', 'code postal', 'postleitzahl', 'plz', 'cep',
    'cap', 'posta kodu', 'почтовый индекс', 'индекс', '邮编', '郵便番号', 'الرمز البريدي', 'पिन कोड',
  ],
  country: ['country', 'pais', 'pays', 'land', 'paese', 'ulke', 'страна', '国家', '国', 'الدوله', 'البلد', 'देश'],
  bday: [
    'birthday', 'date of birth', 'birth date', 'birthdate', 'dob', 'fecha de nacimiento', 'date de naissance',
    'geburtsdatum', 'data de nascimento', 'data di nascita', 'дата рождения', '出生日期', '生年月日',
    'تاريخ الميلاد', 'जन्म तिथि',
  ],
  search: [
    'search', 'find', 'buscar', 'busqueda', 'rechercher', 'recherche', 'suche', 'suchen', 'pesquisar', 'cerca',
    'поиск', '搜索', '搜尋', '検索', 'بحث', 'खोज',
  ],
  // Words around a form (buttons, headings) rather than on a field.
  login: [
    'sign in', 'signin', 'log in', 'login', 'log on', 'logon', 'forgot', 'remember me', 'keep me signed in',
    'iniciar sesion', 'ingresar', 'entrar', 'acceder', 'olvidaste', 'connexion', 'se connecter', 'oublie',
    'anmelden', 'einloggen', 'vergessen', 'acessar', 'esqueceu', 'accedi', 'giris yap', 'войти', 'вход',
    'забыли', '登录', '登入', '忘记密码', 'ログイン', 'サインイン', 'تسجيل الدخول', 'دخول', 'نسيت', 'लॉग इन',
    'साइन इन', 'प्रवेश',
  ],
  signup: [
    'sign up', 'signup', 'register', 'registration', 'create account', 'create an account', 'create your account',
    'join', 'get started', 'i agree', 'terms', 'registrate', 'registrarse', 'crear cuenta', 'inscription',
    "s'inscrire", 'creer un compte', 'registrieren', 'konto erstellen', 'cadastre', 'cadastrar', 'criar conta',
    'registrati', 'kayit ol', 'регистрация', 'зарегистрироваться', 'создать аккаунт', '注册', '註冊', '创建账户',
    '新規登録', 'アカウント作成', 'إنشاء حساب', 'انشاء حساب', 'تسجيل', 'اشترك', 'साइन अप', 'रजिस्टर', 'खाता बनाएं',
  ],
  change: [
    'change password', 'update password', 'reset password', 'new password', 'cambiar contrasena',
    'changer le mot de passe', 'passwort andern', 'alterar senha', 'cambia password', 'сменить пароль',
    'изменить пароль', '修改密码', '更改密码', 'パスワード変更', 'パスワードを変更', 'تغيير كلمه المرور',
    'पासवर्ड बदलें',
  ],
  next: ['next', 'continue', 'siguiente', 'continuar', 'suivant', 'continuer', 'weiter', 'proximo', 'avanti', 'далее', 'продолжить', '下一步', '继续', '次へ', 'التالي', 'متابعه', 'आगे', 'जारी रखें'],
} as const;

export type Concept = keyof typeof TEXT;

const LATIN = /^[a-z0-9 '/.-]+$/;

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** Latin keywords match at a word start ('name' in 'last name' but not in 'username'); spaces are optional. */
function compile(list: readonly string[]): RegExp {
  // Longest first: alternation takes the first branch that matches, and 'email address' must beat 'email'.
  const keywords = list.map(normalize).sort((a, b) => b.length - a.length);
  const parts = keywords.map((k) => {
    if (!LATIN.test(k)) return escape(k);
    const body = k.split(' ').map(escape).join('[ _-]?');
    // Short keywords ('apt', 'otp', 'ort') must also end at a word boundary.
    return k.length <= 4 ? `(?<![a-z0-9])${body}(?![a-z])` : `(?<![a-z0-9])${body}`;
  });
  return new RegExp(parts.join('|'), 'u');
}

const COMPILED = Object.fromEntries(Object.entries(TEXT).map(([concept, list]) => [concept, compile(list)])) as Record<
  Concept,
  RegExp
>;

/** The keyword of `concept` found in normalized `text`, if any. */
export function match(concept: Concept, text: string): string | undefined {
  return COMPILED[concept].exec(text)?.[0];
}

// Identifiers developers use in name/id attributes that the word lists don't catch ('pwd', 'ccnum').
export const ATTRIBUTE: Partial<Record<Concept, RegExp>> = {
  username: /^(user|usr|uname|login|logon|signin|account|acct|uid|userid|j_username|loginid|handle)$|user ?name|login ?(id|name)|account ?name/,
  email: /e ?mail/,
  password: /pass ?(word|wd)?$|^pass|pwd|passwd|^pw$|j_password/,
  new: /new|create|^pw1$|password1$/,
  confirm: /confirm|repeat|retype|again|verify|^pw2$|password2$|^re ?pass/,
  current: /current|old|existing|^pw0$/,
  'one-time-code': /otp|totp|mfa|2fa|two ?factor|one ?time|verification ?code|auth ?code|sms ?code|^code$|^token$|pin ?code/,
  'cc-number': /card ?(number|num|no)|cc ?(number|num|no)|^ccn$|^pan$|creditcard/,
  'cc-name': /card ?holder|holder ?name|name ?on ?card|cc ?name|card ?name/,
  'cc-exp': /exp(iry|iration|ire)? ?(date)?$|cc ?exp$|^mmyy$|valid ?thru/,
  'cc-csc': /cvv|cvc|csc|cvn|security ?code|card ?code|^cid$/,
  month: /month|^mm$|exp ?m(onth)?$/,
  year: /year|^yy(yy)?$|exp ?y(ear)?$/,
  'given-name': /first ?name|given ?name|fname|^first$|forename/,
  'family-name': /last ?name|family ?name|surname|lname|^last$/,
  name: /full ?name|^name$|your ?name|display ?name/,
  tel: /phone|mobile|^tel|cell/,
  organization: /company|organi[sz]ation|^org$|business/,
  'address-line2': /address ?(line)? ?2|addr2|apartment|^apt|suite|^unit$/,
  'address-line1': /address ?(line)? ?1?$|addr1?$|street/,
  'address-level2': /city|town|locality/,
  'address-level1': /state|province|region|county/,
  'postal-code': /zip|postal|postcode|^plz$|^cep$/,
  country: /country/,
  bday: /birth|bday|dob/,
  search: /^q$|^s$|search|query|keyword/,
};
