/**
 * Tests for RemediationTable (packages/ui-kit/src/components/remediation-table.tsx).
 *
 * Boundary contract: renders exactly one <tr> body row per action passed in,
 * and each row's cells contain that action's action/effort/impact text.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RemediationTable } from './remediation-table';

describe('RemediationTable', () => {
  it('renders one row per remediation action', () => {
    render(
      <RemediationTable
        actions={[
          { priority: 1, action: 'Patch CVE-2025-1234', effort: 'low', impact: 'high' },
          { priority: 2, action: 'Rotate leaked credentials', effort: 'medium', impact: 'high' },
          { priority: 3, action: 'Enable MFA', effort: 'low', impact: 'medium' },
        ]}
      />
    );

    expect(screen.getByText('Patch CVE-2025-1234')).toBeTruthy();
    expect(screen.getByText('Rotate leaked credentials')).toBeTruthy();
    expect(screen.getByText('Enable MFA')).toBeTruthy();

    const rows = screen.getAllByRole('row');
    // 1 header row + 3 body rows
    expect(rows.length).toBe(4);
  });

  it('renders an empty table body when given no actions', () => {
    render(<RemediationTable actions={[]} />);
    const rows = screen.getAllByRole('row');
    expect(rows.length).toBe(1); // header row only
  });
});
