const passport = require("passport");
const User = require("../auth/User");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github").Strategy;

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
    },
    function (email, password, done) {
      User.findOne({ email })
        .then((user) => {
          if (!user) {
            return done(null, false, { message: "Incorrect email" });
          }
          bcrypt.compare(password, user.password, function (err, result) {
            if (err) {
              return done(err);
            }
            if (result) {
              return done(null, user);
            } else {
              return done(null, false, { message: "Incorrect password" });
            }
          });
        })
        .catch((e) => {
          return done(e);
        });
    }
  )
);

passport.use(
  new GoogleStrategy(
    {
      clientID:
        "312298164338-ql8vl2c89jbuo91q25vt86i3ahih5h37.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:8000/api/auth/google",
      scope: ["openid", "email", "profile"],
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        const foundUser = await User.findOne({ googleId: profile.id });
        if (foundUser) {
          return cb(null, foundUser);
        } else {
          const newUser = await new User({
            googleId: profile.id,
            full_name: profile.displayName,
            email: profile.emails[0].value,
            description: "Пока ничего о себе не писал...",
          }).save();
          return cb(null, newUser);
        }
      } catch (error) {
        return cb(error);
      }
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: "Ov23liC6VNcQ5JEOzWxn",
      clientSecret: "501ef5b7d57b237f8f624c98676fc646f8175299",
      callbackURL: "http://localhost:8000/api/auth/github",
      scope: ["user", "email"],
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        const foundUser = await User.findOne({ githubId: profile.id });
        if (foundUser) {
          return cb(null, foundUser);
        } else {
          const newUser = await new User({
            githubId: profile.id,
            full_name: profile.displayName,
            email: profile.email,
            description: "Пока ничего о себе не писал...",
          }).save();
          return cb(null, newUser);
        }
      } catch (error) {
        return cb(error);
      }
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user._id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id).then((user, err) => {
    done(err, user);
  });
});
