/**
 * Tests for MitreTechniqueChip (packages/ui-kit/src/components/mitre-technique-chip.tsx).
 *
 * Boundary contract: the technique id always renders; the technique name
 * renders alongside it only when provided.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MitreTechniqueChip } from './mitre-technique-chip';

describe('MitreTechniqueChip', () => {
  it('renders just the technique id when no name is given', () => {
    render(<MitreTechniqueChip techniqueId="T1190" />);
    expect(screen.getByText('T1190')).toBeTruthy();
  });

  it('renders the technique name alongside the id when given', () => {
    render(<MitreTechniqueChip techniqueId="T1190" techniqueName="Exploit Public-Facing Application" />);
    expect(screen.getByText('T1190')).toBeTruthy();
    expect(screen.getByText(/Exploit Public-Facing Application/)).toBeTruthy();
  });
});
