import { decodeWire, encodeWire } from './wire';

const roundTrip = async (value: unknown) => decodeWire(JSON.parse(JSON.stringify(await encodeWire(value))));

describe('wire encoding', () => {
  it('keeps bytes through JSON', async () => {
    const out = (await roundTrip({ args: ['id', new Uint8Array([0, 1, 254, 255])] })) as { args: [string, Uint8Array] };
    expect(out.args[0]).toBe('id');
    expect(out.args[1]).toBeInstanceOf(Uint8Array);
    expect([...out.args[1]]).toEqual([0, 1, 254, 255]);
  });

  it('keeps Blobs and Files with their type and name', async () => {
    const [blob, file] = (await roundTrip([new Blob(['{"a":1}'], { type: 'application/json' }), new File(['x,y'], 'export.csv', { type: 'text/csv', lastModified: 5 })])) as [Blob, File];
    expect(blob).toBeInstanceOf(Blob);
    expect(blob.type).toBe('application/json');
    expect(await blob.text()).toBe('{"a":1}');
    expect(file).toBeInstanceOf(File);
    expect([file.name, file.type, file.lastModified, await file.text()]).toEqual(['export.csv', 'text/csv', 5, 'x,y']);
  });

  it('leaves ordinary values alone', async () => {
    const value = { a: [1, 'two', null, { b: true }], c: undefined };
    expect(await roundTrip(value)).toEqual({ a: [1, 'two', null, { b: true }] });
  });
});
