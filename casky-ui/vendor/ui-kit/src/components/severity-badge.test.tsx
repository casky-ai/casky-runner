/**
 * Tests for SeverityBadge (packages/ui-kit/src/components/severity-badge.tsx).
 *
 * Boundary contract:
 *   1. Each of the 5 Severity values renders its own real Tailwind color
 *      class from SEVERITY_BADGE_CLASSES (tokens.ts) — this is the single
 *      source of truth carried over from apps/web's SEVERITY_COLORS map,
 *      so a drift here is a drift from the app's actual severity coloring.
 *   2. The severity text itself is rendered as visible content.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityBadge } from './severity-badge';
import { SEVERITY_BADGE_CLASSES } from '../tokens';
import type { Severity } from '../types';

describe('SeverityBadge', () => {
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

  for (const severity of severities) {
    it(`renders the correct color class for "${severity}"`, () => {
      render(<SeverityBadge severity={severity} />);
      const badge = screen.getByText(severity);
      const expectedClasses = SEVERITY_BADGE_CLASSES[severity].split(' ');
      for (const cls of expectedClasses) {
        expect(badge.className).toContain(cls);
      }
    });
  }

  it('merges a custom className without dropping the severity color', () => {
    render(<SeverityBadge severity="critical" className="ml-2" />);
    const badge = screen.getByText('critical');
    expect(badge.className).toContain('ml-2');
    expect(badge.className).toContain('bg-red-100');
  });
});
