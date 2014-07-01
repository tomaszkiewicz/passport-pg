passport-pg
=========

passport-pg enables you to run passport authentication with PostgreSQL backend.

## Installation

```js
npm install passport
npm install passport-pg
```

## Configuration

To enable authentication using passport-pg in your existing infrastructure you have to and add some passport's code and call passportPg

```js
var passportPg = require('passport-eg');
passportPg(connectionString, passport, app);
```

The arguments are:

* connectionString - connestion string to your PostgreSQL database
* passport - passport object
* app - your express app


## Example

```js
var express = require('express');
var http = require('http');
var passportPg = require('passport-eg');
var passport = require('passport');

var app = express();

app.set('port', process.env.PORT || 4000);

app.use(express.logger('dev'));
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.session({ secret: 'secret' }));
app.use(passport.initialize());
app.use(passport.session());

var config = require('./config');

passportPg(config.connectionString, passport, app);

http.createServer(app).listen(app.get('port'), function(){
    console.log('Express server listening on port ' + app.get('port'));
});
```

## Version

0.1.0

## License

BSD-3

## Tests

Not yet available

## Release History

* 0.1.0 Initial release