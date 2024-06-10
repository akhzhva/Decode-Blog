const express = require("express");
const passport = require("passport");
const router = express.Router();
const { signUp, signIn, signOut } = require("./controller");
const { deleteUser, editUser } = require("./profile");
const { isAuth } = require("./middlewares");

router.post("/api/signup", signUp);
router.post(
  "/api/signin",
  passport.authenticate("local", { failureRedirect: "/auth?error=1" }),
  signIn
);
router.get("/api/signout", signOut);
router.get("/api/auth/google", passport.authenticate("google"), (req, res) => {
  res.redirect("/myblogs/" + req.user._id);
});
router.get("/api/auth/github", passport.authenticate("github"), (req, res) => {
  res.redirect("/myblogs/" + req.user._id);
});

router.post("/api/user_edit", isAuth, editUser)
router.delete("/api/user_delete/:id", isAuth, deleteUser);

module.exports = router;
