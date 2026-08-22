/**
 * Tests for ConfidenceMeter (packages/ui-kit/src/components/confidence-meter.tsx).
 *
 * Boundary contract: a 0-1 confidence fraction is converted to a 0-100
 * percentage for both the visible label and the progressbar's ARIA value,
 * and out-of-range input is clamped rather than producing an invalid
 * percentage.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ConfidenceMeter } from './confidence-meter';

describe('ConfidenceMeter', () => {
  it('renders 0.73 as 73%', () => {
    render(<ConfidenceMeter confidence={0.73} />);
    expect(screen.getByText('73%')).toBeTruthy();
    expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe('73');
  });

  it('clamps values above 1 to 100%', () => {
    render(<ConfidenceMeter confidence={1.4} />);
    expect(screen.getByText('100%')).toBeTruthy();
  });

  it('clamps negative values to 0%', () => {
    render(<ConfidenceMeter confidence={-0.2} />);
    expect(screen.getByText('0%')).toBeTruthy();
  });
});
