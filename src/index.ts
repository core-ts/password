import * as util from 'util';

export interface Tables {
  user: string;
  password: string;
  history: string;
}
export interface TablesConfig {
  user: string;
  password?: string;
  history?: string;
}
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
  id?: string;
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
  load(id: ID): Promise<Passcode|null|undefined>;
  delete(id: ID): Promise<number>;
}
export interface User<ID> {
  id: ID;
  username: string;
  password: string;
  contact: string;
}
export interface PasswordRepository<ID> {
  getUser(userNameOrEmail: string, exludePassword?: boolean): Promise<User<ID>|null|undefined>;
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
      const histories = await this.repository.getHistory(user.id, this.duplicateCount);
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
      const histories = await this.repository.getHistory(user.id, this.duplicateCount);
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
      const length = Math.min(count, histories.length);
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

export function initTables(c: TablesConfig): Tables {
  const co: Tables = {user: c.user, password: c.user, history: c.user};
  if (c.password && c.password.length > 0) {
    co.password = c.password;
  }
  co.history = (c.history && c.history.length > 0 ? c.history : co.password);
  return co;
}
export function useRepository<ID>(db: DB, c: TablesConfig, max?: number, fields?: FieldConfig): Repository<ID> {
  const conf = initTables(c);
  if (fields) {
    return new Repository<ID>(db, conf, fields.id, fields.contact, fields.username, fields.password, fields.history, fields.changedTime, fields.failCount, max);
  } else {
    return new Repository<ID>(db, conf, undefined, undefined, undefined, undefined, undefined, undefined, undefined, max);
  }
}
export const usePasswordRepository = useRepository;
export const useMongoPasswordRepository = useRepository;
export interface StringMap {
  [key: string]: string;
}
export interface Statement {
  query: string;
  params?: any[];
}
export interface DB {
  param(i: number): string;
  exec(sql: string, args?: any[], ctx?: any): Promise<number>;
  execBatch(statements: Statement[], firstSuccess?: boolean, ctx?: any): Promise<number>;
  query<T>(sql: string, args?: any[], m?: StringMap): Promise<T[]>;
}
export class Repository<ID> {
  max: number;
  id: string;
  contact: string;
  username: string;
  password: string;
  history: string;
  constructor(
    public db: DB,
    public tables: Tables,
    id?: string,
    contact?: string,
    username?: string,
    password?: string,
    history?: string,
    public changedTime?: string,
    public failCount?: string,
    max?: number,
  ) {
    this.max = (max !== undefined ? max + 1: 8);
    this.id = (id && id.length > 0 ? id : 'id');
    this.username = (username && username.length > 0 ? username : 'username');
    this.contact = (contact && contact.length > 0 ? contact : 'email');
    this.password = (password && password.length > 0 ? password : 'password');
    this.history = (history && history.length > 0 ? history : 'history');
    this.getUser = this.getUser.bind(this);
    this.update = this.update.bind(this);
    this.getHistory = this.getHistory.bind(this);
  }
  getUser(userNameOrEmail: string, exludePassword?: boolean): Promise<User<ID>|null|undefined> {
    let query = `
        select ${this.id} as id, ${this.username} as username, ${this.contact} as contact from ${this.tables.user} where ${this.username} = ${this.db.param(1)} union
        select ${this.id} as id, ${this.username} as username, ${this.contact} as contact from ${this.tables.user} where ${this.contact} = ${this.db.param(2)}`;
    if (!exludePassword) {
      if (this.tables.user === this.tables.password) {
        query = `
          select ${this.id} as id, ${this.username} as username, ${this.contact} as contact, ${this.password} as password from ${this.tables.user} where ${this.username} = ${this.db.param(1)} union
          select ${this.id} as id, ${this.username} as username, ${this.contact} as contact, ${this.password} as password from ${this.tables.user} where ${this.contact} = ${this.db.param(2)}`;
      } else {
        query = `
          select u.${this.id} as id, u.${this.username} as username, u.${this.contact} as contact, p.${this.password} as password
          from ${this.tables.user} as u
          left join ${this.tables.password} as p
            on u.${this.id} = p.${this.id}
          where ${this.username} = ${this.db.param(1)}
          union
          select u.${this.id} as id, u.${this.username} as username, u.${this.contact} as contact, p.${this.password} as password
          from ${this.tables.user} as u
          left join ${this.tables.password} as p
            on u.${this.id} = p.${this.id}
          where ${this.contact} = ${this.db.param(2)}`;
      }
    }
    return this.db.query<User<ID>>(query, [userNameOrEmail, userNameOrEmail]).then(v => {
      if (!v || v.length === 0) {
        return null;
      } else {
        return v[0];
      }
    });
  }
  update(userId: ID, newPassword: string, oldPassword?: string): Promise<number> {
    const pass: any = {
      [this.password]: newPassword,
    };
    if (this.changedTime && this.changedTime.length > 0) {
      pass[this.changedTime] = new Date();
    }
    if (this.failCount && this.failCount.length > 0) {
      pass[this.failCount] = 0;
    }
    const history = this.history;
    if (oldPassword && history && history.length > 0) {
      const query = `select ${history} from ${this.tables.history} where ${this.id} = ${this.db.param(1)}`;
      return this.db.query(query, [userId]).then(v => {
        if (!v || v.length === 0) {
          const sh = `insert into ${this.tables.history} (${this.id}, ${this.history}) values (${this.db.param(1)}, ${this.db.param(2)})`;
          const h2: string[] = [oldPassword];
          const stmt2: Statement = {query: sh, params: [userId, h2]};
          const stmt = buildUpdateTable(pass, this.db.param, this.tables.password, this.id, userId);
          return this.db.execBatch([stmt, stmt2]);
        } else {
          const his: any = v[0];
          let h2: string[] = [oldPassword];
          if (his) {
            if (his[history]) {
              h2 = his[history];
            }
            if (h2) {
              h2.push(oldPassword);
            }
            while (h2.length > this.max) {
              h2.shift();
            }
          }
          if (this.tables.password === this.tables.history) {
            pass[history] = h2;
            const stmt = buildUpdateTable(pass, this.db.param, this.tables.password, this.id, userId);
            return this.db.exec(stmt.query, stmt.params);
          } else {
            const sh = `update ${this.tables.history} set ${this.history} = ${this.db.param(1)} where ${this.id} = ${this.db.param(2)}`;
            const stmt2: Statement = {query: sh, params: [h2, userId]};
            const stmt1 = buildUpdateTable(pass, this.db.param, this.tables.password, this.id, userId);
            return this.db.execBatch([stmt1, stmt2]);
          }
        }
      });
    } else {
      const stmt = buildUpdateTable(pass, this.db.param, this.tables.password, this.id, userId);
      return this.db.exec(stmt.query, stmt.params);
    }
  }
  getHistory(userId: ID, max?: number): Promise<string[]> {
    const history = this.history;
    if (history && history.length > 0) {
      const query = `select ${history} from ${this.tables.history} where ${this.id} = ${this.db.param(1)}`;
      return this.db.query(query, [userId]).then(v => {
        if (!v || v.length === 0) {
          return [];
        } else {
          const his: any = v[0];
          if (his) {
            const k = his[history];
            if (Array.isArray(k)) {
              if (max !== undefined && max > 0) {
                while (k.length > max) {
                  k.shift();
                }
                return k;
              } else {
                return k as string[];
              }
            } else {
              return [];
            }
          } else {
            return [];
          }
        }
      });
    } else {
      return Promise.resolve([]);
    }
  }
}
export function buildUpdateTable<ID, T>(pass: T, buildParam: (i: number) => string, table: string, idName: string, id: ID): Statement {
  const stmt = buildUpdate(pass, buildParam);
  const k = stmt.params ? stmt.params.length + 1 : 1;
  const query = `update ${table} set ${stmt.query} where ${idName} = ${buildParam(k)}`;
  const params: any[] = [];
  if (stmt.params && stmt.params.length > 0) {
    for (const pr of stmt.params) {
      params.push(pr);
    }
  }
  params.push(id);
  stmt.query = query;
  stmt.params = params;
  return stmt;
}
export function buildUpdate<T>(obj: T, buildParam: (i: number) => string): Statement {
  const keys = Object.keys(obj as any);
  const cols: string[] = [];
  const params: any[] = [];
  const o: any = obj;
  let i = 1;
  for (const key of keys) {
    const v = o[key];
    if (v != null) {
      cols.push(`${key} = ${buildParam(i++)}`);
      params.push(v);
    } else if (v == null) {
      cols.push(`${key} = null`);
    }
  }
  const query = cols.join(',');
  return { query, params};
}
export const SqlRepository = Repository;
export const PasswordRepository = Repository;
export const SqlPasswordRepository = Repository;
export const Service = Repository;
export const SqlService = Repository;
export const SqlPasswordService = Repository;
