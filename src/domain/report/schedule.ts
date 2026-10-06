import type { Freq } from './report.repository.interface.js';

/** The latest moment a schedule should have fired by `now` (server local time): daily 07:30, Monday 08:00, Friday 16:00, 1st 09:00. */
export function latestSlot(freq: Freq, now: Date): Date {
  const at = (d: Date, h: number, m: number) => new Date(d.getFullYear(), d.getMonth(), d.getDate(), h, m);
  if (freq === 'daily') {
    const today = at(now, 7, 30);
    return today <= now ? today : at(new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1), 7, 30);
  }
  if (freq === 'monthly') {
    const thisMonth = at(new Date(now.getFullYear(), now.getMonth(), 1), 9, 0);
    return thisMonth <= now ? thisMonth : at(new Date(now.getFullYear(), now.getMonth() - 1, 1), 9, 0);
  }
  const [weekday, h, m] = freq === 'weekly-mon' ? [1, 8, 0] : [5, 16, 0];
  const behind = (now.getDay() - weekday! + 7) % 7;
  const candidate = at(new Date(now.getFullYear(), now.getMonth(), now.getDate() - behind), h!, m!);
  return candidate <= now ? candidate : at(new Date(candidate.getFullYear(), candidate.getMonth(), candidate.getDate() - 7), h!, m!);
}

const needsQuoting = /[",\r\n]/;
export function toCsv(header: string[], rows: (string | number | boolean | null)[][]): string {
  const cell = (v: string | number | boolean | null) => {
    if (v === null) return '';
    const s = String(v);
    // Spreadsheet formula injection: a leading =,+,-,@ makes Excel run the cell.
    const safe = /^[=+\-@]/.test(s) && typeof v === 'string' ? `'${s}` : s;
    return needsQuoting.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  // BOM so Excel reads the file as UTF-8.
  return `﻿${[header, ...rows].map((r) => r.map(cell).join(',')).join('\r\n')}\r\n`;
}
