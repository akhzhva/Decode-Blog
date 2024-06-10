const express = require("express");
const app = express();
const session = require("express-session");
const mongooseStore = require("connect-mongo");
const passport = require("passport");
const bodyParser = require("body-parser");

require("./server/config/db");
require("./server/config/passport");

app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    name: "decode_blog.session",
    secret: "keyboard cat",
    maxAge: 1000 * 60 * 60 * 7,
    resave: false,
    saveUninitialized: false,
    store: mongooseStore.create({
      mongoUrl: "mongodb://localhost:27017",
    }),
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(require("./server/pages/router"));
app.use(require("./server/auth/router"));
app.use(require("./server/Category/router"));
app.use(require("./server/Blogs/router"));
app.use(require("./server/Comments/router"));

const PORT = 8000;
app.listen(PORT, () => {
  console.log(`Listening on PORT ${PORT}`);
});
