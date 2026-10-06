export type TemplateId = 'exec' | 'kev' | 'sla' | 'owner';
export type Freq = 'daily' | 'weekly-mon' | 'weekly-fri' | 'monthly';
export type Format = 'csv';

export interface Schedule {
  id: string;
  template: TemplateId;
  scope: string | null;
  freq: Freq;
  recipients: string[];
  formats: Format[];
  enabled: boolean;
  createdAt: Date;
}
export type NewSchedule = Omit<Schedule, 'id' | 'createdAt'>;

export interface Run {
  id: string;
  scheduleId: string | null;
  template: TemplateId;
  scope: string | null;
  formats: Format[];
  status: 'ready' | 'failed' | 'generating';
  manual: boolean;
  sizeBytes: number | null;
  error: string | null;
  createdAt: Date;
}
export type NewRun = Pick<Run, 'scheduleId' | 'template' | 'scope' | 'formats' | 'manual'> & { createdBy: string | null };

export type Cell = string | number | boolean | null;
export interface Table {
  header: string[];
  rows: Cell[][];
}

export interface IReportRepository {
  schedules(): Promise<Schedule[]>;
  createSchedule(input: NewSchedule): Promise<Schedule>;
  updateSchedule(id: string, patch: Partial<NewSchedule>): Promise<Schedule | null>;
  deleteSchedule(id: string): Promise<boolean>;

  runs(limit: number): Promise<Run[]>;
  findRun(id: string): Promise<Run | null>;
  createRun(input: NewRun): Promise<Run>;
  finishRun(id: string, result: { status: 'ready'; content: string } | { status: 'failed'; error: string }): Promise<void>;
  content(id: string): Promise<string | null>;

  /** the table a template shows; `periodDays` bounds "new / closed" figures */
  data(template: TemplateId, scope: string | null, periodDays: number): Promise<Table>;
}
