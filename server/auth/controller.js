const User = require("./User");
const bcrypt = require("bcrypt");

const signUp = async (req, res) => {
  try {
    if (
      req.body.email.length <= 0 &&
      req.body.full_name.length <= 0 &&
      req.body.password.length <= 0 &&
      req.body.re_password.length <= 0
    ) {
      return res.redirect("/reg?error=1");
    } else if (req.body.password !== req.body.re_password) {
      return res.redirect("/reg?error=2");
    }

    const findUser = await User.findOne({
      email: req.body.email,
    }).countDocuments();
    if (findUser) {
      return res.redirect("/reg?error=3");
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password, salt);

    await new User({
      email: req.body.email,
      full_name: req.body.full_name,
      password: hash,
      description: "Пока ничего о себе не писал...",
    }).save();

    res.redirect("/auth");
  } catch (error) {
    console.error(error);
    res.redirect("/reg?error=6");
  }
};

const signIn = (req, res) => {
  res.redirect(`/myblogs/${req.user._id}`);
};

const signOut = (req, res) => {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  });
};

module.exports = {
  signUp,
  signIn,
  signOut,
};
