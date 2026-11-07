import { classifyFields } from './classify/form';
import { scores } from './classify/field';
import { walk, type Walk, type WalkOptions } from './dom/walk';
import type { Field, FieldType, Form, FormType, Scan, Signal } from './types';

export interface DetailedScan extends Scan {
  walk: Walk;
}

export function scanDocument(doc: Document = document, options: WalkOptions = {}): DetailedScan {
  const result = walk(doc, options);
  return { forms: classifyFields(result.fields), frames: result.frames, walk: result };
}

export interface Explanation {
  type: FieldType;
  fillable: boolean;
  formType: FormType;
  /** Total score per candidate type, highest first. */
  scores: [FieldType, number][];
  signals: Signal[];
  formReasons: string[];
  /** The same as a readable text, for logs and the "why did this fill?" debug view. */
  text: string;
}

export function explainField(field: Field, form: Form): Explanation {
  const ranked = [...scores(field.signals)].sort((a, b) => b[1] - a[1]);
  const lines = [
    `${field.type}${field.fillable ? '' : ' (not fillable: hidden, too small, read-only or transparent)'}`,
    ...field.signals.map((s) => `  ${s.score > 0 ? `+${s.score}` : '  ·'} ${s.type}: ${s.reason}`),
    `form: ${form.type}`,
    ...form.reasons.map((r) => `  ${r}`),
  ];
  return {
    type: field.type,
    fillable: field.fillable,
    formType: form.type,
    scores: ranked,
    signals: field.signals,
    formReasons: form.reasons,
    text: lines.join('\n'),
  };
}
