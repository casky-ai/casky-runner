/**
 * Tests for KeyFindingsTable (packages/ui-kit/src/components/key-findings-table.tsx).
 *
 * Boundary contract: renders exactly one <tr> body row per finding passed
 * in, each showing its severity badge text and title/description.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { KeyFindingsTable } from './key-findings-table';

describe('KeyFindingsTable', () => {
  it('renders one row per finding', () => {
    render(
      <KeyFindingsTable
        findings={[
          { title: 'SQL injection in /search', severity: 'critical', description: 'Unsanitized input.' },
          { title: 'Outdated TLS config', severity: 'medium', description: 'TLS 1.0 still enabled.' },
        ]}
      />
    );

    expect(screen.getByText('SQL injection in /search')).toBeTruthy();
    expect(screen.getByText('Outdated TLS config')).toBeTruthy();

    const rows = screen.getAllByRole('row');
    expect(rows.length).toBe(3); // 1 header + 2 body rows
  });
});
