/**
 * Tests for MarkdownReport (packages/ui-kit/src/components/markdown-report.tsx).
 *
 * Boundary contract: basic markdown constructs (headers, lists, bold) are
 * transformed into their corresponding HTML elements, not left as raw
 * markdown text in the DOM.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MarkdownReport } from './markdown-report';

describe('MarkdownReport', () => {
  it('renders a header as an <h2>', () => {
    render(<MarkdownReport markdown="## Executive Summary" />);
    const heading = screen.getByRole('heading', { level: 2 });
    expect(heading.textContent).toBe('Executive Summary');
  });

  it('renders a bullet list as <ul><li>', () => {
    const { container } = render(<MarkdownReport markdown={'- one\n- two\n- three'} />);
    const items = container.querySelectorAll('ul li');
    expect(items.length).toBe(3);
    expect(items[0].textContent).toBe('one');
  });

  it('renders bold text as <strong>', () => {
    const { container } = render(<MarkdownReport markdown="This is **important**." />);
    const strong = container.querySelector('strong');
    expect(strong?.textContent).toBe('important');
  });
});
