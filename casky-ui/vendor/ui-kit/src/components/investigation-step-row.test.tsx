/**
 * Tests for InvestigationStepRow (packages/ui-kit/src/components/investigation-step-row.tsx).
 *
 * Boundary contract: the rendered status icon's aria-label reflects the
 * `status` prop for each of the 4 states (pending/running/done/failed) —
 * this is the only reliable, implementation-detail-free way to assert
 * "the right icon shows for the right status" against lucide-react's SVGs.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { InvestigationStepRow } from './investigation-step-row';
import type { StepStatus } from '../types';

describe('InvestigationStepRow', () => {
  const statuses: StepStatus[] = ['pending', 'running', 'done', 'failed'];

  for (const status of statuses) {
    it(`shows the icon for status "${status}"`, () => {
      render(<InvestigationStepRow skill_slug="port-scan" rationale="Discover open ports" status={status} />);
      expect(screen.getByLabelText(`status: ${status}`)).toBeTruthy();
    });
  }

  it('renders the skill slug and rationale text', () => {
    render(<InvestigationStepRow skill_slug="tls-audit" rationale="Check cert expiry" status="pending" />);
    expect(screen.getByText('tls-audit')).toBeTruthy();
    expect(screen.getByText('Check cert expiry')).toBeTruthy();
  });

  it('does not crash when rationale is omitted', () => {
    render(<InvestigationStepRow skill_slug="tls-audit" status="done" />);
    expect(screen.getByText('tls-audit')).toBeTruthy();
  });
});
