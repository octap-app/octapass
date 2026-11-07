// packages/ui's design tokens as Swift and Kotlin constants.

import {
  argb,
  fontFamilies,
  parseColor,
  parseCubicBezier,
  parseLinearGradient,
  parseRules,
  quantize,
  resolveVars,
  toMilliseconds,
  toPoints,
} from './css.mjs';
import { identifier, kotlinName, swiftName, uniqueNames } from './names.mjs';
import { GENERATED_NOTE as STRINGS_NOTE } from './strings.mjs';

export const GENERATED_NOTE = STRINGS_NOTE.replace(
  'apps/web/src/i18n/{en,ar}.ts and apps/web/src/i18n/phone.ts',
  'packages/ui/src/styles/tokens.css',
).replace('change the catalogs', 'change the tokens');

const LIGHT = [':root'];
const DARK = [":root[data-theme='dark']"];
const DARK_MEDIA = ['@media (prefers-color-scheme: dark)', ":root:not([data-theme='light'])"];

/**
 * Tokens that have no native counterpart (yet). Anything not listed here or understood below is an
 * error. `--field-min` only stops iOS web views zooming into small fields; native fields don't.
 */
export const SKIPPED = /^--(shadow|field-min$)/;

/** `--text-2xl` → `xl2`, `--line-strong` → `lineStrong`: digits up front move to the end. */
export function tokenName(rest) {
  return identifier(rest.replace(/^(\d+)(.*)$/, '$2$1'));
}

const same = (a, b) => a.size === b.size && [...a].every(([k, v]) => b.get(k) === v);

/** The light and dark values of every custom property, the dark ones on top of the light. */
export function themes(css) {
  const rules = parseRules(css);
  // Every rule with exactly this selector path, later ones on top, as the cascade would.
  const find = (path) => {
    const matching = rules.filter((r) => r.path.length === path.length && r.path.every((p, i) => p === path[i]));
    return matching.length ? { declarations: new Map(matching.flatMap((r) => [...r.declarations])) } : undefined;
  };
  const light = find(LIGHT);
  const dark = find(DARK);
  if (!light || !dark) throw new Error('tokens.css needs a :root rule and a :root[data-theme=dark] rule');
  const media = find(DARK_MEDIA);
  if (media && !same(media.declarations, dark.declarations)) throw new Error("tokens.css: the prefers-color-scheme dark values differ from [data-theme='dark']");
  return { light: light.declarations, dark: new Map([...light.declarations, ...dark.declarations]) };
}

export function buildTokens(css) {
  const { light, dark } = themes(css);
  const model = { colors: [], gradients: [], typeScale: [], radii: [], durations: [], easings: [], fonts: [], skipped: [] };
  for (const [token, raw] of light) {
    const lightValue = resolveVars(raw, light);
    const darkValue = resolveVars(dark.get(token), dark);
    const rest = token.slice(2);
    if (SKIPPED.test(token)) model.skipped.push(token);
    else if (rest.startsWith('font-')) model.fonts.push({ token, name: tokenName(rest.slice(5)), families: fontFamilies(lightValue) });
    else if (rest.startsWith('text-')) {
      model.typeScale.push({ token, name: tokenName(rest.slice(5)), points: toPoints(lightValue), css: lightValue, fluid: lightValue.startsWith('clamp(') });
    } else if (rest === 'radius' || rest.startsWith('radius-')) {
      model.radii.push({ token, name: rest === 'radius' ? 'base' : tokenName(rest.slice(7)), points: toPoints(lightValue), css: lightValue });
    } else if (parseCubicBezier(lightValue)) model.easings.push({ token, name: tokenName(rest), points: parseCubicBezier(lightValue) });
    else if (toMilliseconds(lightValue) !== null) model.durations.push({ token, name: tokenName(rest), ms: toMilliseconds(lightValue) });
    else if (parseLinearGradient(lightValue)) {
      const l = parseLinearGradient(lightValue);
      const d = parseLinearGradient(darkValue);
      if (l.stops.length !== d.stops.length || l.angle !== d.angle) throw new Error(`${token}: the dark gradient has a different shape`);
      model.gradients.push({
        token,
        name: tokenName(rest),
        angle: l.angle,
        stops: l.stops.map((s, i) => ({ location: s.location, light: quantize(s.color), dark: quantize(d.stops[i].color) })),
      });
    } else if (parseColor(lightValue)) {
      const darkColor = parseColor(darkValue);
      if (!darkColor) throw new Error(`${token}: the dark value isn't a colour`);
      model.colors.push({ token, name: tokenName(rest), light: quantize(parseColor(lightValue)), dark: quantize(darkColor), css: raw });
    } else throw new Error(`${token}: ${raw} isn't a token the generator knows; teach lib/tokens.mjs or skip it`);
  }
  for (const group of ['colors', 'gradients', 'typeScale', 'radii', 'durations', 'easings', 'fonts']) {
    uniqueNames(
      model[group].map((t) => t.token),
      (token) => model[group].find((t) => t.token === token).name,
      `${group} token`,
    );
  }
  return model;
}

// Swift -------------------------------------------------------------------------------------------

const hex = (rgb) => `0x${rgb.toString(16).toUpperCase().padStart(6, '0')}`;
const num = (n) => String(Math.round(n * 10000) / 10000);
const swiftRGBA = (c) => (c.alpha === 1 ? `RGBA(${hex(c.rgb)})` : `RGBA(${hex(c.rgb)}, alpha: ${num(c.alpha)})`);
const swiftThemed = (light, dark) => `ThemedColor(light: ${swiftRGBA(light)}, dark: ${swiftRGBA(dark)})`;
const singleGradient = (model) => {
  if (model.gradients.length > 1) throw new Error('More than one gradient token: give each its own namespace in lib/tokens.mjs');
  return model.gradients[0];
};

export function swiftTokens(model) {
  const gradient = singleGradient(model);
  const L = [];
  const p = (s = '') => L.push(s);
  p(`// ${GENERATED_NOTE}`);
  p('//');
  p('// Octa Pass design tokens: every colour with its light and dark value, the brand gradient, type');
  p('// sizes and corner radii in points (16 per CSS rem; a size that is fluid on the web, clamp(), is');
  p('// its minimum here, since phones are narrow), motion, and font family names.');
  p();
  p('import Foundation');
  p('#if canImport(SwiftUI)');
  p('import SwiftUI');
  p('#endif');
  p('#if canImport(UIKit)');
  p('import UIKit');
  p('#elseif canImport(AppKit)');
  p('import AppKit');
  p('#endif');
  p();
  p('/// An sRGB colour: `rgb` is 0xRRGGBB, `alpha` 0–1.');
  p('public struct RGBA: Hashable, Sendable {');
  p('    public let rgb: UInt32');
  p('    public let alpha: Double');
  p('    public init(_ rgb: UInt32, alpha: Double = 1) {');
  p('        self.rgb = rgb');
  p('        self.alpha = alpha');
  p('    }');
  p('    public var red: Double { Double((rgb >> 16) & 0xFF) / 255 }');
  p('    public var green: Double { Double((rgb >> 8) & 0xFF) / 255 }');
  p('    public var blue: Double { Double(rgb & 0xFF) / 255 }');
  p('}');
  p();
  p('/// A colour token: its value in light and in dark appearance.');
  p('public struct ThemedColor: Hashable, Sendable {');
  p('    public let light: RGBA');
  p('    public let dark: RGBA');
  p('    public init(light: RGBA, dark: RGBA) {');
  p('        self.light = light');
  p('        self.dark = dark');
  p('    }');
  p('}');
  p();
  p('/// A gradient stop: its colour and its 0–1 location along the gradient.');
  p('public struct GradientStop: Hashable, Sendable {');
  p('    public let color: ThemedColor');
  p('    public let location: Double');
  p('}');
  p();
  p('/// A CSS `cubic-bezier(x1, y1, x2, y2)` timing curve.');
  p('public struct CubicBezier: Hashable, Sendable {');
  p('    public let x1: Double, y1: Double, x2: Double, y2: Double');
  p('}');
  p();
  p('public enum Tokens {');
  p('    public enum Colors {');
  for (const c of model.colors) {
    p(`        /// \`${c.token}: ${c.css}\``);
    p(`        public static let ${swiftName(c.name)} = ${swiftThemed(c.light, c.dark)}`);
  }
  p();
  p('        /// Every colour by its CSS name, without the leading `--`.');
  p('        public static let all: [String: ThemedColor] = [');
  for (const c of model.colors) p(`            "${c.token.slice(2)}": ${swiftName(c.name)},`);
  p('        ]');
  p('    }');
  p();
  if (gradient) {
    p(`    /// \`${gradient.token}\`: the brand gradient: for the logo, at most one headline per screen and hero glows, never behind body text (brand/README.md).`);
    p('    public enum Gradient {');
    p('        /// The CSS angle in degrees: 0 points up, 90 right, clockwise.');
    p(`        public static let angle: Double = ${num(gradient.angle)}`);
    p('        public static let stops: [GradientStop] = [');
    for (const s of gradient.stops) p(`            GradientStop(color: ${swiftThemed(s.light, s.dark)}, location: ${num(s.location)}),`);
    p('        ]');
    p('    }');
    p();
  }
  p('    /// Font sizes in points.');
  p('    public enum TypeScale {');
  for (const t of model.typeScale) {
    p(`        /// \`${t.token}: ${t.css}\`${t.fluid ? ' (the minimum)' : ''}`);
    p(`        public static let ${swiftName(t.name)}: CGFloat = ${num(t.points)}`);
  }
  p('    }');
  p();
  p('    /// Corner radii in points.');
  p('    public enum Radius {');
  for (const r of model.radii) {
    p(`        /// \`${r.token}: ${r.css}\``);
    p(`        public static let ${swiftName(r.name)}: CGFloat = ${num(r.points)}`);
  }
  p('    }');
  p();
  p('    public enum Motion {');
  for (const d of model.durations) {
    p(`        /// \`${d.token}: ${d.ms}ms\``);
    p(`        public static let ${swiftName(d.name)}: TimeInterval = ${num(d.ms / 1000)}`);
  }
  for (const e of model.easings) {
    p(`        /// \`${e.token}: cubic-bezier(${e.points.join(', ')})\``);
    p(`        public static let ${swiftName(e.name)} = CubicBezier(x1: ${num(e.points[0])}, y1: ${num(e.points[1])}, x2: ${num(e.points[2])}, y2: ${num(e.points[3])})`);
  }
  p('    }');
  p();
  p('    /// Font family names. The fonts themselves ship with the app.');
  p('    public enum Fonts {');
  for (const f of model.fonts) {
    p(`        /// \`${f.token}\``);
    p(`        public static let ${swiftName(f.name)} = ${JSON.stringify(f.families[0])}`);
    if (f.families.length > 1) {
      p(`        /// \`${f.token}\` with its fallbacks, first choice first.`);
      p(`        public static let ${swiftName(`${f.name}Families`)} = [${f.families.map((n) => JSON.stringify(n)).join(', ')}]`);
    }
  }
  p('    }');
  p('}');
  p();
  p('#if canImport(UIKit)');
  p('extension RGBA {');
  p('    public var uiColor: UIColor { UIColor(red: red, green: green, blue: blue, alpha: alpha) }');
  p('}');
  p();
  p('extension ThemedColor {');
  p('    /// A UIColor that follows the light or dark appearance.');
  p('    public var uiColor: UIColor {');
  p('        #if os(watchOS)');
  p('        // A watch is always dark, and UIKit there has no dynamic colours.');
  p('        dark.uiColor');
  p('        #else');
  p('        let light = light.uiColor, dark = dark.uiColor');
  p('        return UIColor { $0.userInterfaceStyle == .dark ? dark : light }');
  p('        #endif');
  p('    }');
  p('}');
  p('#elseif canImport(AppKit)');
  p('extension RGBA {');
  p('    public var nsColor: NSColor { NSColor(srgbRed: red, green: green, blue: blue, alpha: alpha) }');
  p('}');
  p();
  p('extension ThemedColor {');
  p('    /// An NSColor that follows the light or dark appearance.');
  p('    public var nsColor: NSColor {');
  p('        let light = light.nsColor, dark = dark.nsColor');
  p('        return NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light }');
  p('    }');
  p('}');
  p('#endif');
  p();
  p('#if canImport(SwiftUI)');
  p('extension RGBA {');
  p('    public var color: Color { Color(.sRGB, red: red, green: green, blue: blue, opacity: alpha) }');
  p('}');
  p();
  p('extension ThemedColor {');
  p('    /// A Color that follows the light or dark appearance.');
  p('    public var color: Color {');
  p('        #if canImport(UIKit)');
  p('        Color(uiColor: uiColor)');
  p('        #else');
  p('        Color(nsColor: nsColor)');
  p('        #endif');
  p('    }');
  p('}');
  p();
  p('extension CubicBezier {');
  p('    public func animation(duration: TimeInterval) -> Animation {');
  p('        .timingCurve(x1, y1, x2, y2, duration: duration)');
  p('    }');
  p('}');
  p('#endif');
  return `${L.join('\n')}\n`;
}

// Kotlin ------------------------------------------------------------------------------------------

const kFloat = (n) => `${num(n)}f`;
const kLong = (c) => `0x${argb(c).toString(16).toUpperCase().padStart(8, '0')}L`;

export function kotlinTokens(model) {
  const gradient = singleGradient(model);
  const L = [];
  const p = (s = '') => L.push(s);
  p(`// ${GENERATED_NOTE}`);
  p('//');
  p('// Octa Pass design tokens as plain constants, no Compose dependency: colours are ARGB for');
  p('// androidx.compose.ui.graphics.Color(Long), type sizes are sp and radii dp (16 per CSS rem; a size');
  p('// that is fluid on the web, clamp(), is its minimum here, since phones are narrow), durations are');
  p('// milliseconds.');
  p();
  p('package app.octap.resources');
  p();
  p('/** A CSS `cubic-bezier(x1, y1, x2, y2)`: Compose\'s `CubicBezierEasing(x1, y1, x2, y2)`. */');
  p('data class CubicBezier(val x1: Float, val y1: Float, val x2: Float, val y2: Float)');
  p();
  p('/** A gradient stop: its 0–1 location and ARGB colour. */');
  p('data class GradientStop(val location: Float, val argb: Long)');
  p();
  p('object Tokens {');
  for (const [object, theme] of [
    ['LightColors', 'light'],
    ['DarkColors', 'dark'],
  ]) {
    p(`    /** Every colour in ${theme} appearance, ARGB. */`);
    p(`    object ${object} {`);
    for (const c of model.colors) p(`        const val ${kotlinName(c.name)}: Long = ${kLong(c[theme])} // ${c.token}`);
    p('    }');
    p();
  }
  if (gradient) {
    p(`    /** \`${gradient.token}\`: the brand gradient: for the logo, at most one headline per screen and hero glows, never behind body text (brand/README.md). */`);
    p('    object Gradient {');
    p('        /** The CSS angle in degrees: 0 points up, clockwise. */');
    p(`        const val angleDegrees: Float = ${kFloat(gradient.angle)}`);
    for (const theme of ['light', 'dark']) {
      p(`        val ${theme}Stops: List<GradientStop> = listOf(`);
      for (const s of gradient.stops) p(`            GradientStop(${kFloat(s.location)}, ${kLong(s[theme])}),`);
      p('        )');
    }
    p('    }');
    p();
  }
  p('    /** Font sizes in sp. */');
  p('    object TypeScale {');
  for (const t of model.typeScale) p(`        const val ${kotlinName(t.name)}: Float = ${kFloat(t.points)} // ${t.token}: ${t.css}${t.fluid ? ' (the minimum)' : ''}`);
  p('    }');
  p();
  p('    /** Corner radii in dp. */');
  p('    object Radius {');
  for (const r of model.radii) p(`        const val ${kotlinName(r.name)}: Float = ${kFloat(r.points)} // ${r.token}: ${r.css}`);
  p('    }');
  p();
  p('    object Motion {');
  for (const d of model.durations) p(`        const val ${kotlinName(`${d.name}Millis`)}: Int = ${d.ms} // ${d.token}`);
  for (const e of model.easings) p(`        val ${kotlinName(e.name)} = CubicBezier(${e.points.map(kFloat).join(', ')}) // ${e.token}`);
  p('    }');
  p();
  p('    /** Font family names. The fonts themselves ship with the app. */');
  p('    object Fonts {');
  for (const f of model.fonts) {
    p(`        const val ${kotlinName(f.name)}: String = ${JSON.stringify(f.families[0])} // ${f.token}`);
    if (f.families.length > 1) p(`        val ${kotlinName(`${f.name}Families`)}: List<String> = listOf(${f.families.map((n) => JSON.stringify(n)).join(', ')})`);
  }
  p('    }');
  p('}');
  return `${L.join('\n')}\n`;
}
