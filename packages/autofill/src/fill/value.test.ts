import { chooseOption, setValue } from './value';

/** What React does: an instance `value` property that records what React itself set. */
function trackLikeReact(input: HTMLInputElement): { changes: string[] } {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!;
  let tracked = input.value;
  Object.defineProperty(input, 'value', {
    configurable: true,
    get: () => descriptor.get!.call(input),
    set: (value: string) => {
      tracked = value;
      descriptor.set!.call(input, value);
    },
  });
  const seen = { changes: [] as string[] };
  input.addEventListener('input', () => {
    const current = descriptor.get!.call(input) as string;
    if (current !== tracked) {
      tracked = current;
      seen.changes.push(current);
    }
  });
  return seen;
}

describe('setValue', () => {
  it('makes a React-style controlled input notice the change', () => {
    document.body.innerHTML = '<input>';
    const input = document.querySelector('input')!;
    const react = trackLikeReact(input);
    setValue(input, 'alex');
    expect(react.changes).toEqual(['alex']);
  });

  it('fires input and change', () => {
    document.body.innerHTML = '<input>';
    const input = document.querySelector('input')!;
    const events: string[] = [];
    input.addEventListener('input', (e) => events.push(`${e.type}:${(e as InputEvent).inputType}`));
    input.addEventListener('change', (e) => events.push(e.type));
    setValue(input, 'x');
    expect(events).toEqual(['input:insertReplacementText', 'change']);
  });

  it('picks the matching option of a select', () => {
    document.body.innerHTML = '<select><option value="">--</option><option value="8">August</option><option value="9">September</option></select>';
    const select = document.querySelector('select')!;
    expect(setValue(select, '09', ['September'])).toBe(true);
    expect(select.value).toBe('9');
  });

  it('reports a select with no matching option', () => {
    document.body.innerHTML = '<select><option>A</option></select>';
    expect(setValue(document.querySelector('select')!, 'Z')).toBe(false);
  });
});

describe('chooseOption', () => {
  it('matches value, then number, then a text prefix', () => {
    document.body.innerHTML = `<select><option value="840">United States of America</option><option value="2029">2029</option>
      <option value="m3">03</option></select>`;
    const select = document.querySelector('select')!;
    expect(chooseOption(select, ['US', 'United States'])?.value).toBe('840');
    expect(chooseOption(select, ['3'])?.value).toBe('m3');
    expect(chooseOption(select, ['29', '2029'])?.value).toBe('2029');
  });
});
