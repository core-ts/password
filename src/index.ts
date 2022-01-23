import * as util from 'util';

export interface Collections {
  user: string;
  password: string;
  history: string;
}
export interface CollectionsConfig {
  user: string;
  password?: string;
  history?: string;
}
export interface FieldConfig {
  contact?: string;
  username?: string;
  password?: string;
  history?: string;
  changedTime?: string;
  failCount?: string;
}
export interface Template {
  subject: string;
  body: string;
}
export interface PasswordConfig {
  max?: number;
  expires: number;
  fields?: FieldConfig;
  db: CollectionsConfig;
}
export interface PasswordTemplateConfig extends PasswordConfig {
  templates: {
    reset: Template;
    change: Template;
  };
}
export interface PasswordReset {
  username: string;
  passcode: string;
  password: string;
}
export interface PasswordChange {
  step?: number;
  username: string;
  passcode?: string;
  currentPassword: string;
  password: string;
}
export interface Comparator {
  compare(data: string, encrypted: string): Promise<boolean>;
  hash(plaintext: string): Promise<string>;
}
export interface Passcode {
  expiredAt: Date;
  code: string;
}
export interface PasscodeRepository<ID> {
  save(id: ID, passcode: string, expireAt: Date): Promise<number>;
  load(id: ID): Promise<Passcode>;
  delete(id: ID): Promise<number>;
}
export interface User<ID> {
  id: ID;
  username: string;
  password: string;
  contact: string;
}
export interface PasswordRepository<ID> {
  getUser(userNameOrEmail: string, exludePassword?: boolean): Promise<User<ID>>;
  update(userId: ID, newPassword: string, oldPassword?: string): Promise<number>;
  getHistory(userId: ID, max?: number): Promise<string[]>;
}
/*
export interface PasswordService {
  forgot(email: string): Promise<boolean>;
  reset(pass: PasswordReset): Promise<number>;
  change(pass: PasswordChange): Promise<number>;
}
*/
export class PasswordService<ID> {
  generate: () => string;
  duplicateCount: number;
  constructor(
    public comparator: Comparator,
    public repository: PasswordRepository<ID>,
    public sendResetCode: (to: string, passcode: string, expireAt: Date, params?: any) => Promise<boolean>,
    public expires: number,
    public resetCodeRepository: PasscodeRepository<ID>,
    duplicateCount?: number,
    public revokeTokens?: (id: string, reason?: string) => Promise<boolean>,
    public hasTwoFactors?: (id: ID) => Promise<boolean>,
    gen?: () => string,
    public sendPasscode?: (to: string, passcode: string, expireAt: Date, params?: any) => Promise<boolean>,
    public passwordChangeExpires?: number,
    public passcodeRepository?: PasscodeRepository<ID>
  ) {
    this.generate = (gen ? gen : generate);
    this.duplicateCount = (duplicateCount !== undefined ? duplicateCount : 0);
    this.change = this.change.bind(this);
    this.forgot = this.forgot.bind(this);
    this.reset = this.reset.bind(this);
    this.duplicate = this.duplicate.bind(this);
  }

  async change(pass: PasswordChange): Promise<number> {
    if (pass.step && pass.step > 0 && (!pass.passcode || pass.passcode.length === 0)) {
      return 0;
    }
    const user = await this.repository.getUser(pass.username);
    if (!user) {
      return 0;
    }
    if (!user.id) {
      return 0;
    }
    const valid = await this.comparator.compare(pass.currentPassword, user.password);
    if (!valid) {
      return 0;
    }
    if (this.duplicateCount > 0) {
      const histories = await this.repository.getHistory(user.id, this.duplicateCount - 1);
      const isDuplicate = await this.duplicate(pass.password, this.duplicateCount, user.password, histories);
      if (isDuplicate) {
        return -1;
      }
    }
    if (this.hasTwoFactors) {
      const required = await this.hasTwoFactors(user.id);
      if (required) {
        const repo = (this.passcodeRepository ? this.passcodeRepository : this.resetCodeRepository);
        if (!pass.step || pass.step <= 1) {
          const sentCode = this.generate();
          const savedCode = await this.comparator.hash(sentCode);
          const expires = (this.passwordChangeExpires ? this.passwordChangeExpires : this.expires);
          const expiredTime = addSeconds(new Date(), expires);
          const res0 = await repo.save(user.id, savedCode, expiredTime);
          if (res0 > 0) {
            const send = (this.sendPasscode ? this.sendPasscode : this.sendResetCode);
            await send(user.contact, sentCode, expiredTime, user.username);
            return 2;
          }
        } else {
          if (!pass.passcode || pass.passcode.length === 0) {
            return 0;
          }
          const code = await repo.load(user.id);
          if (!code) {
            return 0;
          }
          if (after(new Date(), code.expiredAt)) {
            return 0;
          }
          const validPasscode = await this.comparator.compare(pass.passcode, code.code);
          if (!validPasscode) {
            return 0;
          } else {
            await repo.delete(user.id);
          }
        }
      }
    }
    const newPassword = await this.comparator.hash(pass.password);
    const res = await this.repository.update(user.id, newPassword, user.password);
    if (res > 0) {
      if (this.revokeTokens) {
        await this.revokeTokens('' + user.id, 'The user has changed password.');
      }
      return 1;
    } else {
      return 0;
    }
  }
  forgot(contact: string): Promise<boolean> {
    return this.repository.getUser(contact).then(user => {
      if (!user) {
        return false;
      } else {
        const sentCode = this.generate();
        return this.comparator.hash(sentCode).then(savedCode => {
          const expiredAt = addSeconds(new Date(), this.expires);
          return this.resetCodeRepository.save(user.id, savedCode, expiredAt).then(res => {
            if (res > 0) {
              return this.sendResetCode(user.contact, sentCode, expiredAt, user.username);
            } else {
              return false;
            }
          });
        });
      }
    });
  }
  async reset(pass: PasswordReset): Promise<number> {
    const excludePassword = (this.duplicateCount <= 0);
    const user = await this.repository.getUser(pass.username, excludePassword);
    if (!user) {
      return 0;
    }
    const code = await this.resetCodeRepository.load(user.id);
    if (!code) {
      return 0;
    }
    if (after(new Date(), code.expiredAt)) {
      await this.resetCodeRepository.delete(user.id);
      return 0;
    }
    const valid = await this.comparator.compare(pass.passcode, code.code);
    if (!valid) {
      return 0;
    }
    const newPassword = await this.comparator.hash(pass.password);
    if (this.duplicateCount > 0) {
      const histories = await this.repository.getHistory(user.id, this.duplicateCount - 1);
      const isDuplicate = await this.duplicate(pass.password, this.duplicateCount, user.password, histories);
      if (isDuplicate) {
        return -1;
      }
    }
    const oldPassword = (this.duplicateCount > 0 ? user.password : undefined);
    const res =  await this.repository.update(user.id, newPassword, oldPassword);
    if (res > 0) {
      if (this.revokeTokens) {
        await this.revokeTokens('' + user.id, 'The user has reset password.');
      }
      return 1;
    } else {
      return 0;
    }
  }
  private async duplicate(newPassword: string, count: number, currentPassword: string, histories: string[]): Promise<boolean> {
    if (currentPassword && currentPassword.length > 0) {
      const equal = await this.comparator.compare(newPassword, currentPassword);
      if (equal) {
        return equal;
      }
    }
    if (histories && histories.length > 0) {
      const length = Math.min(count - 2, histories.length);
      const l = histories.length;
      for (let i = 1; i <= length; i++) {
        const equal = await this.comparator.compare(newPassword, histories[l - i]);
        if (equal) {
          return equal;
        }
      }
    }
    return false;
  }
}
export function addSeconds(date: Date, seconds: number) {
  const d = new Date(date);
  d.setSeconds(d.getSeconds() + seconds);
  return d;
}
export function after(d1: Date, d2: Date): boolean {
  return (d1.getTime() - d2.getTime() > 0);
}
export function generate(length?: number): string {
  if (!length) {
    length = 6;
  }
  return padLeft(Math.floor(Math.random() * Math.floor(Math.pow(10, length) - 1)).toString(), length, '0');
}
export function padLeft(str: string, length: number, pad: string) {
  if (str.length >= length) {
    return str;
  }
  let str2 = str;
  while (str2.length < length) {
    str2 = pad + str2;
  }
  return str2;
}
export type EmailData = string|{ name?: string; email: string; };
export interface MailContent {
  type: string;
  value: string;
}
export interface MailData {
  to?: EmailData|EmailData[];

  from: EmailData;
  replyTo?: EmailData;

  subject?: string;
  html?: string;
  content?: MailContent[];
}
// tslint:disable-next-line:max-classes-per-file
export class MailSender {
  constructor(
    public sendMail: (mailData: MailData) => Promise<boolean>,
    public from: EmailData,
    public body: string,
    public subject: string
  ) {
    this.send = this.send.bind(this);
  }
  send(to: string, passcode: string, expireAt: Date, params?: any): Promise<boolean> {
    const diff =  Math.abs(Math.round(((Date.now() - expireAt.getTime()) / 1000) / 60));
    const body = util.format(this.body, ...[params as string, passcode, diff, params, passcode, diff]);
    const msg = {
      to,
      from: this.from,
      subject: this.subject,
      html: body
    };
    return this.sendMail(msg);
  }
}
