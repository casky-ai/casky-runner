import { twMerge } from 'tailwind-merge';

/**
 * Merge Tailwind class lists, letting later classes win over earlier
 * conflicting ones (via tailwind-merge) and dropping falsy values.
 */
export function cn(...classes: Array<string | false | null | undefined>): string {
  return twMerge(classes.filter(Boolean).join(' '));
}
