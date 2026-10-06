import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Actor } from '../../../application/shared/actor.js';
import type { ClientInfo } from '../../../application/auth/session.service.js';
import { LoginUseCase } from '../../../application/auth/use-cases/login.use-case.js';
import { RefreshSessionUseCase } from '../../../application/auth/use-cases/refresh-session.use-case.js';
import { LogoutUseCase } from '../../../application/auth/use-cases/logout.use-case.js';
import { GetMeUseCase } from '../../../application/auth/use-cases/get-me.use-case.js';
import { ChangePasswordUseCase } from '../../../application/auth/use-cases/change-password.use-case.js';
import { GetAuthTokenInfoUseCase, RegisterWithInviteUseCase, ResetPasswordUseCase } from '../../../application/auth/use-cases/auth-token.use-cases.js';

@injectable()
export class AuthController {
  constructor(
    @inject(TYPES.LoginUseCase) private readonly loginUc: LoginUseCase,
    @inject(TYPES.RefreshSessionUseCase)
    private readonly refreshUc: RefreshSessionUseCase,
    @inject(TYPES.LogoutUseCase) private readonly logoutUc: LogoutUseCase,
    @inject(TYPES.GetMeUseCase) private readonly meUc: GetMeUseCase,
    @inject(TYPES.ChangePasswordUseCase)
    private readonly changePasswordUc: ChangePasswordUseCase,
    @inject(TYPES.GetAuthTokenInfoUseCase)
    private readonly tokenInfoUc: GetAuthTokenInfoUseCase,
    @inject(TYPES.RegisterWithInviteUseCase)
    private readonly registerUc: RegisterWithInviteUseCase,
    @inject(TYPES.ResetPasswordUseCase)
    private readonly resetUc: ResetPasswordUseCase,
  ) {}

  //TODO : Parametreleri bu şekilde alınmıcak daha temiz bir yapı olucak

  login(input: { email: string; password: string } & ClientInfo) {
    return this.loginUc.execute(input);
  }
  refresh(token: string, client: ClientInfo) {
    return this.refreshUc.execute(token, client);
  }
  logout(token: string | undefined) {
    return this.logoutUc.execute(token);
  }
  me(userId: string) {
    return this.meUc.execute(userId);
  }
  changePassword(
    a: Actor,
    body: { currentPassword: string; newPassword: string },
  ) {
    return this.changePasswordUc.execute(
      a.id,
      body.currentPassword,
      body.newPassword,
      a.ip,
    );
  }
  inviteInfo(token: string) {
    return this.tokenInfoUc.execute(token, "invite");
  }
  resetInfo(token: string) {
    return this.tokenInfoUc.execute(token, "reset");
  }
  register(
    input: { token: string; name: string; password: string } & ClientInfo,
  ) {
    return this.registerUc.execute(input);
  }
  resetPassword(input: { token: string; password: string; ip: string | null }) {
    return this.resetUc.execute(input);
  }
}
