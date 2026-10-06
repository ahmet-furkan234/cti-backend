import { describe, expect, it } from 'vitest';
import { latestSlot, toCsv } from './schedule.js';

describe('latestSlot', () => {
  it('daily: before the time uses yesterday, after it uses today', () => {
    expect(latestSlot('daily', new Date(2026, 9, 6, 7, 0))).toEqual(new Date(2026, 9, 5, 7, 30));
    expect(latestSlot('daily', new Date(2026, 9, 6, 8, 0))).toEqual(new Date(2026, 9, 6, 7, 30));
  });
  it('weekly: finds the last Monday 08:00', () => {
    expect(latestSlot('weekly-mon', new Date(2026, 9, 7, 12, 0))).toEqual(new Date(2026, 9, 5, 8, 0)); // Wed 7 Oct 2026
  });
  it('monthly: the first of the month at 09:00', () => {
    expect(latestSlot('monthly', new Date(2026, 9, 6, 12, 0))).toEqual(new Date(2026, 9, 1, 9, 0));
    expect(latestSlot('monthly', new Date(2026, 9, 1, 8, 0))).toEqual(new Date(2026, 8, 1, 9, 0));
  });
});

describe('toCsv', () => {
  it('quotes commas and quotes, and neutralises spreadsheet formulas', () => {
    const csv = toCsv(['a', 'b'], [['x,y', 'say "hi"'], ['=1+1', 5]]);
    expect(csv).toBe('﻿a,b\r\n"x,y","say ""hi"""\r\n\'=1+1,5\r\n');
  });
});
