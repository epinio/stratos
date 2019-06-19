import { NgModule } from '@angular/core';

import { registerCFEntities } from './cf-entity-generator';
import { CloudFoundryComponentsModule } from './shared/components/components.module';

@NgModule({
  imports: [
    // TODO split out anything lazy loaded into seperate module
    CloudFoundryComponentsModule
  ],
})
export class CloudFoundryPackageModule {
  constructor() {
    this.registerCfFavoriteEntities();
  }
  private registerCfFavoriteEntities() {
    registerCFEntities();
  }

}
