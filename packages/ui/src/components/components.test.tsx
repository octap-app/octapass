import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { Avatar, hueFor } from './Avatar';
import { Button } from './Button';
import { Icon } from './Icon';
import { IconButton } from './IconButton';
import { KeyFingerprint } from './KeyFingerprint';
import { Segmented } from './Segmented';
import { Switch } from './Switch';
import { TextField } from './TextField';
import { onToast, Toaster, useToast } from './Toaster';

describe('Button', () => {
  it('blocks clicks and reports busy while working', async () => {
    const onClick = vi.fn();
    render(<Button busy onClick={onClick}>Save</Button>);
    const button = screen.getByRole('button', { name: 'Save' });
    expect(button).toHaveAttribute('aria-busy', 'true');
    await userEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });
});

describe('Avatar', () => {
  it('shows the initial until the website icon loads, and again if it fails', () => {
    const { container, rerender } = render(<Avatar name="bank" src="data:image/png;base64,AAAA" />);
    const avatar = container.firstElementChild!;
    expect(avatar).toHaveTextContent('B');
    const image = avatar.querySelector('img')!;
    fireEvent.load(image);
    expect(avatar).toHaveTextContent('');
    expect(avatar.querySelector('img')).toBeInTheDocument();
    fireEvent.error(avatar.querySelector('img')!);
    expect(avatar).toHaveTextContent('B');
    expect(avatar.querySelector('img')).toBeNull();
    rerender(<Avatar name="bank" />);
    expect(avatar).toHaveTextContent('B');
  });
});

describe('IconButton', () => {
  it('uses its label as the accessible name', () => {
    render(<IconButton icon="copy" label="Copy password" />);
    expect(screen.getByRole('button', { name: 'Copy password' })).toBeInTheDocument();
  });
});

describe('KeyFingerprint', () => {
  it('shows the six digit groups to read aloud, and names the emoji for screen readers', () => {
    render(<KeyFingerprint label="Fingerprint of sam@example.com" emojiLabel="As pictures" digits="1234 5678 9012 3456 7890 1234" emoji={[{ emoji: '🦊', name: 'fox' }, { emoji: '🌙', name: 'moon' }]} />);
    const figure = screen.getByRole('figure', { name: 'Fingerprint of sam@example.com' });
    expect(figure.querySelectorAll('li')).toHaveLength(6);
    expect(screen.getByLabelText('As pictures: fox, moon')).toBeInTheDocument();
  });
});

describe('TextField', () => {
  it('links the label, and describes the field by its error', () => {
    render(<TextField label="Email" error="Enter an email address." />);
    const input = screen.getByLabelText('Email');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Enter an email address.');
  });
});

describe('Switch', () => {
  it('toggles with a click', async () => {
    function Harness() {
      const [on, setOn] = useState(false);
      return <Switch label="Symbols" checked={on} onChange={setOn} />;
    }
    render(<Harness />);
    const toggle = screen.getByRole('switch', { name: 'Symbols' });
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-checked', 'true');
  });
});

describe('Segmented', () => {
  it('is a radio group', async () => {
    const onChange = vi.fn();
    render(<Segmented label="Kind" value="a" onChange={onChange} options={[{ value: 'a', label: 'Password' }, { value: 'b', label: 'Passphrase' }]} />);
    expect(screen.getByRole('radiogroup', { name: 'Kind' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'Passphrase' }));
    expect(onChange).toHaveBeenCalledWith('b');
  });
});

describe('Toaster', () => {
  it('announces messages in a live region', async () => {
    function Copy() {
      const toast = useToast();
      return <button onClick={() => toast({ message: 'Password copied' })}>Copy</button>;
    }
    render(<Toaster><Copy /></Toaster>);
    await act(() => userEvent.click(screen.getByRole('button', { name: 'Copy' })));
    expect(screen.getByRole('status')).toHaveTextContent('Password copied');
  });

  it('tells listeners about every toast until they unsubscribe', async () => {
    const heard: string[] = [];
    const stop = onToast((toast) => heard.push(`${toast.tone}: ${toast.message}`));
    function Save() {
      const toast = useToast();
      return <button onClick={() => toast({ message: 'Saved', tone: 'success' })}>Save</button>;
    }
    render(<Toaster><Save /></Toaster>);
    await act(() => userEvent.click(screen.getByRole('button', { name: 'Save' })));
    stop();
    await act(() => userEvent.click(screen.getByRole('button', { name: 'Save' })));
    expect(heard).toEqual(['success: Saved']);
  });
});

describe('hueFor', () => {
  it('is stable and case-insensitive', () => {
    expect(hueFor('GitHub')).toBe(hueFor('github'));
    expect(hueFor('GitHub')).toBeGreaterThanOrEqual(0);
    expect(hueFor('GitHub')).toBeLessThan(360);
  });
});

describe('right to left', () => {
  it('mirrors icons that point somewhere, and only those', () => {
    const { container } = render(
      <>
        <Icon name="chevronRight" />
        <Icon name="signOut" />
        <Icon name="check" />
        <Icon name="lock" />
      </>,
    );
    const mirrored = [...container.querySelectorAll('svg')].map((svg) => svg.hasAttribute('data-mirror'));
    expect(mirrored).toEqual([true, true, false, false]);
  });

  it('keeps addresses, numbers and passwords left to right', () => {
    render(
      <>
        <TextField label="Email" type="email" />
        <TextField label="Website" type="url" />
        <TextField label="Code" inputMode="numeric" />
        <TextField label="Key" mono />
        <TextField label="Name" />
        <TextField label="Username" dir="auto" />
      </>,
    );
    for (const label of ['Email', 'Website', 'Code', 'Key']) expect(screen.getByLabelText(label)).toHaveAttribute('dir', 'ltr');
    expect(screen.getByLabelText('Name')).not.toHaveAttribute('dir');
    expect(screen.getByLabelText('Username')).toHaveAttribute('dir', 'auto');
  });

  it('marks an option’s own language', () => {
    render(<Segmented label="Language" value="en" onChange={() => {}} options={[{ value: 'en', label: 'English', lang: 'en' }, { value: 'ar', label: 'العربية', lang: 'ar' }]} />);
    expect(screen.getByText('العربية')).toHaveAttribute('lang', 'ar');
  });
});
