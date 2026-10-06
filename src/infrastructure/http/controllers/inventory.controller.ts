import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { AssetPatch, ListAssetsQuery } from '../../../domain/inventory/inventory.repository.interface.js';
import type { Actor } from '../../../application/shared/actor.js';
import {
  CreateAssetUseCase, DeleteAssetUseCase, GetAssetUseCase, ImportAssetsUseCase, ListAssetsUseCase, ListImportsUseCase,
  UpdateAssetUseCase, CheckSoftwareUseCase, SoftwareCatalogUseCases, type AssetInput, type ImportCommand,
} from '../../../application/inventory/inventory.use-cases.js';

@injectable()
export class InventoryController {
  constructor(
    @inject(TYPES.ListAssetsUseCase) private readonly list_: ListAssetsUseCase,
    @inject(TYPES.GetAssetUseCase) private readonly get_: GetAssetUseCase,
    @inject(TYPES.CreateAssetUseCase) private readonly create_: CreateAssetUseCase,
    @inject(TYPES.UpdateAssetUseCase) private readonly update_: UpdateAssetUseCase,
    @inject(TYPES.DeleteAssetUseCase) private readonly delete_: DeleteAssetUseCase,
    @inject(TYPES.ImportAssetsUseCase) private readonly import_: ImportAssetsUseCase,
    @inject(TYPES.ListImportsUseCase) private readonly imports_: ListImportsUseCase,
    @inject(TYPES.CheckSoftwareUseCase) private readonly check_: CheckSoftwareUseCase,
    @inject(TYPES.SoftwareCatalogUseCases) private readonly catalog_: SoftwareCatalogUseCases,
  ) {}

  list(q: ListAssetsQuery) { return this.list_.execute(q); }
  get(id: string) { return this.get_.execute(id); }
  create(actor: Actor, body: AssetInput) { return this.create_.execute(actor, body); }
  update(actor: Actor, id: string, patch: AssetPatch) { return this.update_.execute(actor, id, patch); }
  delete(actor: Actor, id: string) { return this.delete_.execute(actor, id); }
  import(actor: Actor, cmd: ImportCommand) { return this.import_.execute(actor, cmd); }
  checkSoftware(items: { product: string; version?: string | null }[]) { return this.check_.execute(items); }
  searchProducts(q: string) { return this.catalog_.search(q); }
  aliases() { return this.catalog_.aliases(); }
  createAlias(actor: Actor, body: { name: string; pair: string }) { return this.catalog_.createAlias(actor, body); }
  deleteAlias(actor: Actor, id: string) { return this.catalog_.deleteAlias(actor, id); }
  async imports() { return { items: await this.imports_.execute() }; }
}
