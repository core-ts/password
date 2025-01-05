"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
  function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
  return new (P || (P = Promise))(function (resolve, reject) {
    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
    function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
  var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
  return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
  function verb(n) { return function (v) { return step([n, v]); }; }
  function step(op) {
    if (f) throw new TypeError("Generator is already executing.");
    while (_) try {
      if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
      if (y = 0, t) op = [op[0] & 2, t.value];
      switch (op[0]) {
        case 0: case 1: t = op; break;
        case 4: _.label++; return { value: op[1], done: false };
        case 5: _.label++; y = op[1]; op = [0]; continue;
        case 7: op = _.ops.pop(); _.trys.pop(); continue;
        default:
          if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
          if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
          if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
          if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
          if (t[2]) _.ops.pop();
          _.trys.pop(); continue;
      }
      op = body.call(thisArg, _);
    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
  }
};
var __spreadArrays = (this && this.__spreadArrays) || function () {
  for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
  for (var r = Array(s), k = 0, i = 0; i < il; i++)
    for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
      r[k] = a[j];
  return r;
};
Object.defineProperty(exports, "__esModule", { value: true });
var util = require("util");
var PasswordService = (function () {
  function PasswordService(comparator, repository, sendResetCode, expires, resetCodeRepository, duplicateCount, revokeTokens, hasTwoFactors, gen, sendPasscode, passwordChangeExpires, passcodeRepository) {
    this.comparator = comparator;
    this.repository = repository;
    this.sendResetCode = sendResetCode;
    this.expires = expires;
    this.resetCodeRepository = resetCodeRepository;
    this.revokeTokens = revokeTokens;
    this.hasTwoFactors = hasTwoFactors;
    this.sendPasscode = sendPasscode;
    this.passwordChangeExpires = passwordChangeExpires;
    this.passcodeRepository = passcodeRepository;
    this.generate = (gen ? gen : generate);
    this.duplicateCount = (duplicateCount !== undefined ? duplicateCount : 0);
    this.change = this.change.bind(this);
    this.forgot = this.forgot.bind(this);
    this.reset = this.reset.bind(this);
    this.duplicate = this.duplicate.bind(this);
  }
  PasswordService.prototype.change = function (pass) {
    return __awaiter(this, void 0, void 0, function () {
      var user, valid, histories, isDuplicate, required, repo, sentCode, savedCode, expires, expiredTime, res0, send, code, validPasscode, newPassword, res;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0:
            if (pass.step && pass.step > 0 && (!pass.passcode || pass.passcode.length === 0)) {
              return [2, 0];
            }
            return [4, this.repository.getUser(pass.username)];
          case 1:
            user = _a.sent();
            if (!user) {
              return [2, 0];
            }
            if (!user.id) {
              return [2, 0];
            }
            return [4, this.comparator.compare(pass.currentPassword, user.password)];
          case 2:
            valid = _a.sent();
            if (!valid) {
              return [2, 0];
            }
            if (!(this.duplicateCount > 0)) return [3, 5];
            return [4, this.repository.getHistory(user.id, this.duplicateCount)];
          case 3:
            histories = _a.sent();
            return [4, this.duplicate(pass.password, this.duplicateCount, user.password, histories)];
          case 4:
            isDuplicate = _a.sent();
            if (isDuplicate) {
              return [2, -1];
            }
            _a.label = 5;
          case 5:
            if (!this.hasTwoFactors) return [3, 16];
            return [4, this.hasTwoFactors(user.id)];
          case 6:
            required = _a.sent();
            if (!required) return [3, 16];
            repo = (this.passcodeRepository ? this.passcodeRepository : this.resetCodeRepository);
            if (!(!pass.step || pass.step <= 1)) return [3, 11];
            sentCode = this.generate();
            return [4, this.comparator.hash(sentCode)];
          case 7:
            savedCode = _a.sent();
            expires = (this.passwordChangeExpires ? this.passwordChangeExpires : this.expires);
            expiredTime = addSeconds(new Date(), expires);
            return [4, repo.save(user.id, savedCode, expiredTime)];
          case 8:
            res0 = _a.sent();
            if (!(res0 > 0)) return [3, 10];
            send = (this.sendPasscode ? this.sendPasscode : this.sendResetCode);
            return [4, send(user.contact, sentCode, expiredTime, user.username)];
          case 9:
            _a.sent();
            return [2, 2];
          case 10: return [3, 16];
          case 11:
            if (!pass.passcode || pass.passcode.length === 0) {
              return [2, 0];
            }
            return [4, repo.load(user.id)];
          case 12:
            code = _a.sent();
            if (!code) {
              return [2, 0];
            }
            if (after(new Date(), code.expiredAt)) {
              return [2, 0];
            }
            return [4, this.comparator.compare(pass.passcode, code.code)];
          case 13:
            validPasscode = _a.sent();
            if (!!validPasscode) return [3, 14];
            return [2, 0];
          case 14: return [4, repo.delete(user.id)];
          case 15:
            _a.sent();
            _a.label = 16;
          case 16: return [4, this.comparator.hash(pass.password)];
          case 17:
            newPassword = _a.sent();
            return [4, this.repository.update(user.id, newPassword, user.password)];
          case 18:
            res = _a.sent();
            if (!(res > 0)) return [3, 21];
            if (!this.revokeTokens) return [3, 20];
            return [4, this.revokeTokens('' + user.id, 'The user has changed password.')];
          case 19:
            _a.sent();
            _a.label = 20;
          case 20: return [2, 1];
          case 21: return [2, 0];
        }
      });
    });
  };
  PasswordService.prototype.forgot = function (contact) {
    var _this = this;
    return this.repository.getUser(contact).then(function (user) {
      if (!user) {
        return false;
      }
      else {
        var sentCode_1 = _this.generate();
        return _this.comparator.hash(sentCode_1).then(function (savedCode) {
          var expiredAt = addSeconds(new Date(), _this.expires);
          return _this.resetCodeRepository.save(user.id, savedCode, expiredAt).then(function (res) {
            if (res > 0) {
              return _this.sendResetCode(user.contact, sentCode_1, expiredAt, user.username);
            }
            else {
              return false;
            }
          });
        });
      }
    });
  };
  PasswordService.prototype.reset = function (pass) {
    return __awaiter(this, void 0, void 0, function () {
      var excludePassword, user, code, valid, newPassword, histories, isDuplicate, oldPassword, res;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0:
            excludePassword = (this.duplicateCount <= 0);
            return [4, this.repository.getUser(pass.username, excludePassword)];
          case 1:
            user = _a.sent();
            if (!user) {
              return [2, 0];
            }
            return [4, this.resetCodeRepository.load(user.id)];
          case 2:
            code = _a.sent();
            if (!code) {
              return [2, 0];
            }
            if (!after(new Date(), code.expiredAt)) return [3, 4];
            return [4, this.resetCodeRepository.delete(user.id)];
          case 3:
            _a.sent();
            return [2, 0];
          case 4: return [4, this.comparator.compare(pass.passcode, code.code)];
          case 5:
            valid = _a.sent();
            if (!valid) {
              return [2, 0];
            }
            return [4, this.comparator.hash(pass.password)];
          case 6:
            newPassword = _a.sent();
            if (!(this.duplicateCount > 0)) return [3, 9];
            return [4, this.repository.getHistory(user.id, this.duplicateCount)];
          case 7:
            histories = _a.sent();
            return [4, this.duplicate(pass.password, this.duplicateCount, user.password, histories)];
          case 8:
            isDuplicate = _a.sent();
            if (isDuplicate) {
              return [2, -1];
            }
            _a.label = 9;
          case 9:
            oldPassword = (this.duplicateCount > 0 ? user.password : undefined);
            return [4, this.repository.update(user.id, newPassword, oldPassword)];
          case 10:
            res = _a.sent();
            if (!(res > 0)) return [3, 13];
            if (!this.revokeTokens) return [3, 12];
            return [4, this.revokeTokens('' + user.id, 'The user has reset password.')];
          case 11:
            _a.sent();
            _a.label = 12;
          case 12: return [2, 1];
          case 13: return [2, 0];
        }
      });
    });
  };
  PasswordService.prototype.duplicate = function (newPassword, count, currentPassword, histories) {
    return __awaiter(this, void 0, void 0, function () {
      var equal, length, l, i, equal;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0:
            if (!(currentPassword && currentPassword.length > 0)) return [3, 2];
            return [4, this.comparator.compare(newPassword, currentPassword)];
          case 1:
            equal = _a.sent();
            if (equal) {
              return [2, equal];
            }
            _a.label = 2;
          case 2:
            if (!(histories && histories.length > 0)) return [3, 6];
            length = Math.min(count, histories.length);
            l = histories.length;
            i = 1;
            _a.label = 3;
          case 3:
            if (!(i <= length)) return [3, 6];
            return [4, this.comparator.compare(newPassword, histories[l - i])];
          case 4:
            equal = _a.sent();
            if (equal) {
              return [2, equal];
            }
            _a.label = 5;
          case 5:
            i++;
            return [3, 3];
          case 6: return [2, false];
        }
      });
    });
  };
  return PasswordService;
}());
exports.PasswordService = PasswordService;
function addSeconds(date, seconds) {
  var d = new Date(date);
  d.setSeconds(d.getSeconds() + seconds);
  return d;
}
exports.addSeconds = addSeconds;
function after(d1, d2) {
  return (d1.getTime() - d2.getTime() > 0);
}
exports.after = after;
function generate(length) {
  if (!length) {
    length = 6;
  }
  return padLeft(Math.floor(Math.random() * Math.floor(Math.pow(10, length) - 1)).toString(), length, '0');
}
exports.generate = generate;
function padLeft(str, length, pad) {
  if (str.length >= length) {
    return str;
  }
  var str2 = str;
  while (str2.length < length) {
    str2 = pad + str2;
  }
  return str2;
}
exports.padLeft = padLeft;
var MailSender = (function () {
  function MailSender(sendMail, from, body, subject) {
    this.sendMail = sendMail;
    this.from = from;
    this.body = body;
    this.subject = subject;
    this.send = this.send.bind(this);
  }
  MailSender.prototype.send = function (to, passcode, expireAt, params) {
    var diff = Math.abs(Math.round(((Date.now() - expireAt.getTime()) / 1000) / 60));
    var body = util.format.apply(util, __spreadArrays([this.body], [params, passcode, diff, params, passcode, diff]));
    var msg = {
      to: to,
      from: this.from,
      subject: this.subject,
      html: body
    };
    return this.sendMail(msg);
  };
  return MailSender;
}());
exports.MailSender = MailSender;
function initTables(c) {
  var co = { user: c.user, password: c.user, history: c.user };
  if (c.password && c.password.length > 0) {
    co.password = c.password;
  }
  co.history = (c.history && c.history.length > 0 ? c.history : co.password);
  return co;
}
exports.initTables = initTables;
function useRepository(db, c, max, fields) {
  var conf = initTables(c);
  if (fields) {
    return new Repository(db, conf, fields.id, fields.contact, fields.username, fields.password, fields.history, fields.changedTime, fields.failCount, max);
  }
  else {
    return new Repository(db, conf, undefined, undefined, undefined, undefined, undefined, undefined, undefined, max);
  }
}
exports.useRepository = useRepository;
exports.usePasswordRepository = useRepository;
exports.useMongoPasswordRepository = useRepository;
var Repository = (function () {
  function Repository(db, tables, id, contact, username, password, history, changedTime, failCount, max) {
    this.db = db;
    this.tables = tables;
    this.changedTime = changedTime;
    this.failCount = failCount;
    this.max = (max !== undefined ? max + 1 : 8);
    this.id = (id && id.length > 0 ? id : 'id');
    this.username = (username && username.length > 0 ? username : 'username');
    this.contact = (contact && contact.length > 0 ? contact : 'email');
    this.password = (password && password.length > 0 ? password : 'password');
    this.history = (history && history.length > 0 ? history : 'history');
    this.getUser = this.getUser.bind(this);
    this.update = this.update.bind(this);
    this.getHistory = this.getHistory.bind(this);
  }
  Repository.prototype.getUser = function (userNameOrEmail, exludePassword) {
    var query = "\n    select " + this.id + " as id, " + this.username + " as username, " + this.contact + " as contact from " + this.tables.user + " where " + this.username + " = " + this.db.param(1) + " union\n    select " + this.id + " as id, " + this.username + " as username, " + this.contact + " as contact from " + this.tables.user + " where " + this.contact + " = " + this.db.param(2);
    if (!exludePassword) {
      if (this.tables.user === this.tables.password) {
        query = "\n      select " + this.id + " as id, " + this.username + " as username, " + this.contact + " as contact, " + this.password + " as password from " + this.tables.user + " where " + this.username + " = " + this.db.param(1) + " union\n      select " + this.id + " as id, " + this.username + " as username, " + this.contact + " as contact, " + this.password + " as password from " + this.tables.user + " where " + this.contact + " = " + this.db.param(2);
      }
      else {
        query = "\n      select u." + this.id + " as id, u." + this.username + " as username, u." + this.contact + " as contact, p." + this.password + " as password\n      from " + this.tables.user + " as u\n      left join " + this.tables.password + " as p\n      on u." + this.id + " = p." + this.id + "\n      where " + this.username + " = " + this.db.param(1) + "\n      union\n      select u." + this.id + " as id, u." + this.username + " as username, u." + this.contact + " as contact, p." + this.password + " as password\n      from " + this.tables.user + " as u\n      left join " + this.tables.password + " as p\n      on u." + this.id + " = p." + this.id + "\n      where " + this.contact + " = " + this.db.param(2);
      }
    }
    return this.db.query(query, [userNameOrEmail, userNameOrEmail]).then(function (v) {
      if (!v || v.length === 0) {
        return null;
      }
      else {
        return v[0];
      }
    });
  };
  Repository.prototype.update = function (userId, newPassword, oldPassword) {
    var _a;
    var _this = this;
    var pass = (_a = {},
      _a[this.password] = newPassword,
      _a);
    if (this.changedTime && this.changedTime.length > 0) {
      pass[this.changedTime] = new Date();
    }
    if (this.failCount && this.failCount.length > 0) {
      pass[this.failCount] = 0;
    }
    var history = this.history;
    if (oldPassword && history && history.length > 0) {
      var query = "select " + history + " from " + this.tables.history + " where " + this.id + " = " + this.db.param(1);
      return this.db.query(query, [userId]).then(function (v) {
        if (!v || v.length === 0) {
          var sh = "insert into " + _this.tables.history + " (" + _this.id + ", " + _this.history + ") values (" + _this.db.param(1) + ", " + _this.db.param(2) + ")";
          var h2 = [oldPassword];
          var stmt2 = { query: sh, params: [userId, h2] };
          var stmt = buildUpdateTable(pass, _this.db.param, _this.tables.password, _this.id, userId);
          return _this.db.execBatch([stmt, stmt2]);
        }
        else {
          var his = v[0];
          var h2 = [oldPassword];
          if (his) {
            if (his[history]) {
              h2 = his[history];
            }
            if (h2) {
              h2.push(oldPassword);
            }
            while (h2.length > _this.max) {
              h2.shift();
            }
          }
          if (_this.tables.password === _this.tables.history) {
            pass[history] = h2;
            var stmt = buildUpdateTable(pass, _this.db.param, _this.tables.password, _this.id, userId);
            return _this.db.exec(stmt.query, stmt.params);
          }
          else {
            var sh = "update " + _this.tables.history + " set " + _this.history + " = " + _this.db.param(1) + " where " + _this.id + " = " + _this.db.param(2);
            var stmt2 = { query: sh, params: [h2, userId] };
            var stmt1 = buildUpdateTable(pass, _this.db.param, _this.tables.password, _this.id, userId);
            return _this.db.execBatch([stmt1, stmt2]);
          }
        }
      });
    }
    else {
      var stmt = buildUpdateTable(pass, this.db.param, this.tables.password, this.id, userId);
      return this.db.exec(stmt.query, stmt.params);
    }
  };
  Repository.prototype.getHistory = function (userId, max) {
    var history = this.history;
    if (history && history.length > 0) {
      var query = "select " + history + " from " + this.tables.history + " where " + this.id + " = " + this.db.param(1);
      return this.db.query(query, [userId]).then(function (v) {
        if (!v || v.length === 0) {
          return [];
        }
        else {
          var his = v[0];
          if (his) {
            var k = his[history];
            if (Array.isArray(k)) {
              if (max !== undefined && max > 0) {
                while (k.length > max) {
                  k.shift();
                }
                return k;
              }
              else {
                return k;
              }
            }
            else {
              return [];
            }
          }
          else {
            return [];
          }
        }
      });
    }
    else {
      return Promise.resolve([]);
    }
  };
  return Repository;
}());
exports.Repository = Repository;
function buildUpdateTable(pass, buildParam, table, idName, id) {
  var stmt = buildUpdate(pass, buildParam);
  var k = stmt.params ? stmt.params.length + 1 : 1;
  var query = "update " + table + " set " + stmt.query + " where " + idName + " = " + buildParam(k);
  var params = [];
  if (stmt.params && stmt.params.length > 0) {
    for (var _i = 0, _a = stmt.params; _i < _a.length; _i++) {
      var pr = _a[_i];
      params.push(pr);
    }
  }
  params.push(id);
  stmt.query = query;
  stmt.params = params;
  return stmt;
}
exports.buildUpdateTable = buildUpdateTable;
function buildUpdate(obj, buildParam) {
  var keys = Object.keys(obj);
  var cols = [];
  var params = [];
  var o = obj;
  var i = 1;
  for (var _i = 0, keys_1 = keys; _i < keys_1.length; _i++) {
    var key = keys_1[_i];
    var v = o[key];
    if (v != null) {
      cols.push(key + " = " + buildParam(i++));
      params.push(v);
    }
    else if (v == null) {
      cols.push(key + " = null");
    }
  }
  var query = cols.join(',');
  return { query: query, params: params };
}
exports.buildUpdate = buildUpdate;
exports.SqlRepository = Repository;
exports.PasswordRepository = Repository;
exports.SqlPasswordRepository = Repository;
exports.Service = Repository;
exports.SqlService = Repository;
exports.SqlPasswordService = Repository;
