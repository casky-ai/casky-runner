/**
 * Tests for FindingCard (packages/ui-kit/src/components/finding-card.tsx).
 *
 * Boundary contract:
 *   1. All provided fields (title, description, cvss_score, affected_asset,
 *      mitre_technique_id, remediation, raw_evidence) render somewhere in
 *      the card.
 *   2. Omitting every optional field never throws and never renders the
 *      optional sections (no "undefined" leaking into the DOM) — this is
 *      the contract that lets apps/web pass a raw `findings` row (which has
 *      many nullable columns) straight through as props.
 *   3. `actions` and `footer` slots render when provided, so app-specific
 *      controls (status selector, feedback widget, run link) can be
 *      composed in without FindingCard needing to know about them.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { FindingCard } from './finding-card';

describe('FindingCard', () => {
  it('renders all provided fields', () => {
    render(
      <FindingCard
        title="Exposed admin panel"
        description="The admin panel is reachable without authentication."
        severity="high"
        cvss_score={7.5}
        affected_asset="10.0.0.5:8080"
        remediation="Restrict access via firewall rule."
        raw_evidence="curl -I http://10.0.0.5:8080/admin"
        mitre_technique_id="T1190"
        status="open"
      />
    );

    expect(screen.getByText('Exposed admin panel')).toBeTruthy();
    expect(screen.getByText(/admin panel is reachable/)).toBeTruthy();
    expect(screen.getByText('CVSS 7.5')).toBeTruthy();
    expect(screen.getByText('10.0.0.5:8080')).toBeTruthy();
    expect(screen.getByText('T1190')).toBeTruthy();
    expect(screen.getByText('Remediation steps')).toBeTruthy();
    expect(screen.getByText('Raw evidence')).toBeTruthy();
    expect(screen.getByText('high')).toBeTruthy();
  });

  it('does not crash and skips optional sections when only required fields are given', () => {
    render(<FindingCard title="Bare finding" severity="low" />);

    expect(screen.getByText('Bare finding')).toBeTruthy();
    expect(screen.queryByText('CVSS', { exact: false })).toBeNull();
    expect(screen.queryByText('Remediation steps')).toBeNull();
    expect(screen.queryByText('Raw evidence')).toBeNull();
  });

  it('renders the actions and footer slots when provided', () => {
    render(
      <FindingCard
        title="With slots"
        severity="medium"
        actions={<span>status: open</span>}
        footer={<span>footer content</span>}
      />
    );

    expect(screen.getByText('status: open')).toBeTruthy();
    expect(screen.getByText('footer content')).toBeTruthy();
  });
});
