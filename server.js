/*
Deploying to `now`. Example:
$ now secret add server-url https://piratepanda.now.sh
$ now secret add jwt-secret some-secret-here
$ now secret add oauth-cookie-secret some-other-secret-here
$ now -e SERVER_URL=@server-url -e JWT_SECRET=@jwt-secret -e OAUTH_COOKIE_SECRET=@oauth-cookie-secret --public
$ now alias hapipanda-wpyfhyutrv piratepanda
*/

const Hapi = require("hapi");
const Hoek = require("hoek");
const Good = require("good");
const Bell = require("bell");
const HapiAuthJWT = require("hapi-auth-jwt2");
const JWT = require("jsonwebtoken");
const googleCredentials = require("./google.json");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error(
    "JWT_SECRET must be defined as an environment variable. (How to generate a secret key: https://github.com/dwyl/hapi-auth-jwt2#generating-your-secret-key)"
  );
}
const OAUTH_COOKIE_SECRET = process.env.OAUTH_COOKIE_SECRET;
if (!OAUTH_COOKIE_SECRET) {
  throw new Error(
    "OAUTH_COOKIE_SECRET must be defined as an environment variable."
  );
}

const SERVER_URL = process.env.SERVER_URL;
if (!SERVER_URL) {
  throw new Error(
    "SERVER_URL, e.g. 'https://piratepanda.now.sh', must be defined as an environment variable."
  );
}

const people = {
  // our "users database"
  1: {
    id: 1,
    name: "Jen Jones"
  },
  2: {
    id: 2,
    name: "Ada Lovelace"
  },
  "114874691531207529332": {
    id: "114874691531207529332",
    name: "Robin"
  }
};

const getUser = request => {
  const token = request.headers.authorization || request.query.token;
  const decoded = JWT.decode(token, JWT_SECRET);
  return people[decoded.id];
};

const server = new Hapi.Server();
server.connection({ port: 3006, host: "localhost" });

server.register(Bell, err => {
  Hoek.assert(!err, err);
  server.auth.strategy("google", "bell", {
    provider: "google",
    password: OAUTH_COOKIE_SECRET,
    isSecure: false,
    clientId: googleCredentials.clientId,
    clientSecret: googleCredentials.clientSecret,
    // `server.info.uri` should work well usually. On now that'll end up being
    // localhost though so we specify the location explicitly.
    location: SERVER_URL
  });

  server.register(HapiAuthJWT, err => {
    if (err) console.log(err);

    const strategyName = "jwt";

    server.auth.strategy(strategyName, "jwt", {
      key: JWT_SECRET,
      validateFunc: (decoded, request, cb) => {
        // Additional validation goes here, e.g. we could store user sessions in Redis
        // and check if the user is "logged in". Right now we simply let the token be
        // valid until its expiry.
        return cb(null, true);
      },
      verifyOptions: { algorithms: ["HS256"] }
    });

    server.auth.default(strategyName);

    server.route([
      {
        method: "GET",
        path: "/",
        config: { auth: false },
        handler: (request, reply) => reply({ text: "Token not required" })
      },
      // Authenticate the user via Google OAuth2 and if successful return a JSON
      // WEB TOKEN (JWT).
      {
        method: ["GET", "POST"],
        path: "/login",
        config: {
          auth: {
            strategy: "google",
            mode: "try"
          }
        },
        handler: (request, reply) => {
          if (!request.auth.isAuthenticated) {
            return reply(
              `Authentication failed due to ${request.auth.error.message}`
            );
          }

          // Hand out a token.
          const token = JWT.sign(
            {
              id: request.auth.credentials.profile.id, // matches user id stored in `people`
              exp: Math.floor(Date.now() / 1000 + 60 * 60) // expires 60 minutes from now
            },
            JWT_SECRET
          );

          reply({
            text: "Tokens for the select few! Check your authorization header."
          }).header("Authorization", token);
        }
      },
      {
        method: "GET",
        path: "/profile",
        handler: (request, reply) => {
          const user = getUser(request);
          reply(user);
        }
      },
      {
        method: "GET",
        path: "/{name}",
        handler: function(request, reply) {
          reply("Hello, " + encodeURIComponent(request.params.name) + "!");
        }
      }
    ]);
  });
});

server.register(
  {
    register: Good,
    options: {
      reporters: {
        console: [
          {
            module: "good-squeeze",
            name: "Squeeze",
            args: [
              {
                response: "*",
                log: "*"
              }
            ]
          },
          {
            module: "good-console"
          },
          "stdout"
        ]
      }
    }
  },
  err => {
    if (err) {
      throw err; // something bad happened loading the plugin
    }

    server.start(err => {
      if (err) {
        throw err;
      }
      server.log("info", "Server running at: " + SERVER_URL);
    });
  }
);
