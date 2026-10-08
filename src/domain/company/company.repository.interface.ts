export type CompanyStatus = 'active' | 'suspended';

export interface Company {
  id: string;
  name: string;
  isPlatform: boolean;
  status: CompanyStatus;
  createdAt: Date;
}

export interface CompanyListItem extends Company {
  users: number;
  assets: number;
}

export interface ICompanyRepository {
  findById(id: string): Promise<Company | null>;
  findByName(name: string): Promise<Company | null>;
  findPlatform(): Promise<Company | null>;
  list(): Promise<CompanyListItem[]>;
  /** companies whose background work (alerts, reports) should run */
  active(): Promise<Company[]>;
  create(input: { name: string }): Promise<Company>;
  update(id: string, patch: { name?: string; status?: CompanyStatus }): Promise<Company | null>;
}
