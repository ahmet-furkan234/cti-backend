export interface Role {
  id: string;
  name: string;
  description: string;
  isSystem: boolean;
  permissionKeys: string[];
  memberCount: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Permission {
  key: string;
  module: string;
  description: string;
}

export interface IRoleRepository {
  list(): Promise<Role[]>;
  findById(id: string): Promise<Role | null>;
  findByIds(ids: string[]): Promise<Role[]>;
  findByName(name: string): Promise<Role | null>;
  create(input: { name: string; description: string; isSystem?: boolean; permissionKeys: string[] }): Promise<Role>;
  update(id: string, input: { name?: string; description?: string; permissionKeys?: string[] }): Promise<Role>;
  delete(id: string): Promise<void>;
  /** User ids holding the role. */
  memberIds(roleId: string): Promise<string[]>;
}

export interface IPermissionRepository {
  list(): Promise<Permission[]>;
  keys(): Promise<string[]>;
  syncCatalog(items: Permission[]): Promise<void>;
}
