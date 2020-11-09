import { Component, Inject, OnInit } from '@angular/core';
import { AbstractControl, FormControl, FormGroup, ValidatorFn, Validators } from '@angular/forms';
import { Store } from '@ngrx/store';
import { BehaviorSubject, Observable } from 'rxjs';
import { delay, filter, map, take, tap } from 'rxjs/operators';

import { VerifySession } from '../../../../../store/src/actions/auth.actions';
import { SetupSaveConfig } from '../../../../../store/src/actions/setup.actions';
import { InternalAppState } from '../../../../../store/src/app-state';
import { AuthState } from '../../../../../store/src/reducers/auth.reducer';
import { LocalAdminSetupData, UAASetupState } from '../../../../../store/src/types/uaa-setup.types';
import { APP_TITLE } from '../../../core/core.types';
import { StepOnNextFunction } from '../../../shared/components/stepper/step/step.component';

@Component({
  selector: 'app-local-account-wizard',
  templateUrl: './local-account-wizard.component.html',
  styleUrls: ['./local-account-wizard.component.scss']
})
export class LocalAccountWizardComponent implements OnInit {

  passwordForm: FormGroup;
  validateLocalAuthForm: Observable<boolean>;
  applyingSetup$ = new BehaviorSubject<boolean>(false);

  showPassword: boolean[] = [];

  constructor(private store: Store<Pick<InternalAppState, 'uaaSetup' | 'auth'>>, @Inject(APP_TITLE) public title: string) { }

  ngOnInit() {
    this.passwordForm = new FormGroup({
      adminPassword: new FormControl('', [Validators.required as any]),
      adminPasswordConfirm: new FormControl('', [Validators.required as any])
    });

    this.validateLocalAuthForm = this.passwordForm.valueChanges.pipe(
      tap(() => {
        this.passwordForm.controls.adminPasswordConfirm.setValidators([Validators.required, this.confirmPasswordValidator()]);
      }),
      map(() => this.passwordForm.valid)
    );
  }

  next: StepOnNextFunction = () => {
    const data: LocalAdminSetupData = {
      local_admin_password: this.passwordForm.get('adminPassword').value,
    };

    this.applyingSetup$.next(true);
    this.store.dispatch(new SetupSaveConfig(data));
    return this.store.select(s => [s.uaaSetup, s.auth]).pipe(
      filter(([uaa, auth]: [UAASetupState, AuthState]) => {
        return !(uaa.settingUp || auth.verifying);
      }),
      delay(2000),
      take(10),
      filter(([uaa, auth]: [UAASetupState, AuthState]) => {
        const validUAASessionData = auth.sessionData && !auth.sessionData.uaaError;
        if (!validUAASessionData) {
          this.store.dispatch(new VerifySession());
        }
        return validUAASessionData;
      }),
      map((state: [UAASetupState, AuthState]) => {
        if (!state[0].error) {
          // Do a hard reload of the app
          const loc = window.location;
          const reload = loc.protocol + '//' + loc.host;
          window.location.assign(reload);
        } else {
          this.applyingSetup$.next(false);
        }
        return {
          success: !state[0].error,
          message: state[0].message
        };
      }));
  };

  confirmPasswordValidator(): ValidatorFn {
    return (control: AbstractControl): { [key: string]: any, } => {
      const same = control.value === this.passwordForm.value.adminPassword;
      return same ? null : { passwordMatch: { value: control.value } };
    };
  }
}
