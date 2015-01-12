var pgEscape = require('pg-escape');
var pgPrepare = require('pg/lib/utils');
var pg = require('pg');
var crypto = require('crypto');
var PassportLocalStrategy = require('passport-local').Strategy;

var setPassword = function (password, cb) {
    crypto.randomBytes(32, function(err, buf) {
        if (err) {
            return cb(err);
        }

        var salt = buf.toString('hex');

        crypto.pbkdf2(password, salt, 25000, 512, function(err, hashRaw) {
            if (err)
                return cb(err);

            var hash = new Buffer(hashRaw, 'binary').toString('hex');

            cb(null, hash, salt);
        });
    });
};

var checkPassword = function(hash, salt, password, cb) {
    crypto.pbkdf2(password, salt, 25000, 512, function(err, hashRaw) {
        if (err)
            return cb(err);

        var currentHash = new Buffer(hashRaw, 'binary').toString('hex');

        if (currentHash === hash) {
            return cb(null, true);
        } else {
            return cb(null, false);
        }
    });
};

var cacheByUsername = {};
var cacheById = {};

// TODO implement change password function and invalidate cache when user changes password
var invalidateCache = function(username, id) {
    if(username)
        delete cacheByUsername[username];

    if(id)
        delete cacheById[id];

    if(!username && !id) {
        cacheById = {};
        cacheByUsername = {};
    }
};

var getUser = function(connectionString, username, id, callback) {
    if(username && cacheByUsername[username]) {
        callback(null, cacheByUsername[username]);
        return;
    }

    if(id && cacheById[id]) {
        callback(null, cacheById[id]);
        return;
    }

    pg.connect(connectionString, function (err, client, done) {
        if (err) {
            callback(err);
            return console.error('error fetching client from pool', err);
        }
        client.query('SELECT * FROM users WHERE (username = $1) OR (id = $2)', [ username, id ], function (err, result) {
            done();

            if (err) {
                callback(err);
                return console.error('error running query', err);
            }

            if(result.rows.length == 0) {
              callback(null, null);
              return;
            }

            var user = result.rows[0];

            cacheById[user.id] = user;
            cacheByUsername[user.login] = user;

            callback(null, user);
        });
    });
};

var register = function(connectionString, username, password, callback) {
    setPassword(password, function(err, hash, salt) {
        pg.connect(connectionString, function (err, client, done) {
            if (err) {
                callback(err);
                return console.error('error fetching client from pool', err);
            }
            client.query('INSERT INTO users (username, hash, salt) VALUES ($1, $2, $3) RETURNING id', [ username, hash, salt ], function (err, result) {
                done();

                if (err) {
                    callback(err);
                    return console.error('error running query', err);
                }

                callback(null, result.rows[0]);
            });
        });
    });
};

var authenticate = function (req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(403).send({ result: "unauthenticated" });
};

module.exports = exports = function(connectionString, passport, app, options) {
    options = options || {};
    if(options.enableRegistration == 'undefined')
        options.enableRegistration = true;

    if(!options.authPath)
        options.authPath = '/auth';

    if(!options.registerPath)
        options.registerPath = '/register';


    if(!options.registerWithoutAuthPath)
        options.registerWithoutAuthPath = '/register-noauth';

    passport.use(new PassportLocalStrategy(
        function(username, password, done) {
            getUser(connectionString, username, null, function(err, user) {
                if(err || !user) {
                    done(false);
                    return;
                }

                checkPassword(user.hash, user.salt, password, function(err, result) {
                    if(result)
                        done(null, user);
                    else
                        done(false);
                });
            });
        }
    ));

    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        getUser(connectionString, null, id, function(err, user) {
            delete user.hash;
            delete user.salt;
            done(null, user);
        });

    });

    if(options.enableRegistration) {
        app.post(options.registerPath, function (req, res) {
            register(connectionString, req.body.username, req.body.password, function (err, result) {
                if (err)
                    res.send(err);

                passport.authenticate('local')(req, res, function () {
                    delete req.user.hash;
                    delete req.user.salt;

                    res.send({result: "ok", username: req.user});
                });
            });
        });
        app.post(options.registerWithoutAuthPath, function (req, res) {
            register(connectionString, req.body.username, req.body.password, function (err, result) {
                if (err)
                    res.send(err);
                else
                    res.send({result: "ok", username: req.body.username});
            });
        });
    }

    app.get(options.authPath, authenticate, function(req, res) {
        res.send(req.user);
    });

    app.post(options.authPath, passport.authenticate('local'), function(req, res) {
        delete req.user.hash;
        delete req.user.salt;
        res.send({ result: "ok", user: req.user });
    });

    app.delete(options.authPath, function(req, res) {
        req.logout();
        res.send({ result: "ok" });
    });
};