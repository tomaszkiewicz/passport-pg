var express = require('express');
var http = require('http');
var passportPg = require('..');
var passport = require('passport');

var app = express();

app.set('port', process.env.PORT || 4000);

app.use(express.logger('dev'));
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.session({ secret: 'so secret' }));
app.use(passport.initialize());
app.use(passport.session());

var config = require('./config');

passportPg(config.connectionString, passport, app);

http.createServer(app).listen(app.get('port'), function(){
    console.log('Express server listening on port ' + app.get('port'));
});