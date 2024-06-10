const User = require("./User");
const Blog = require("../Blogs/blog");
const Comment = require("../Comments/Comment");

const deleteUser = async (req, res) => {
  const userToDeleteId = req.params.id;
  try {
    const userToDelete = await User.findById(userToDeleteId);
    if (!userToDelete) {
      return res.status(404).send("Пользователь не найден");
    }

    await Comment.deleteMany({ authorID: userToDeleteId });
    await Blog.deleteMany({ user: userToDeleteId });
    await User.findByIdAndDelete(userToDeleteId);

    console.log(
      `Пользователь с ID ${userToDeleteId} успешно удален вместе со всеми связанными записями.`
    );
    return res.status(200).send("Пользователь успешно удален");
  } catch (error) {
    console.error("Ошибка при удалении пользователя:", error);
    return res.status(500).send("Ошибка при удалении пользователя");
  }
};

const editUser = async (req, res) => {
  if (req.body.full_name.length > 0 && req.body.description.length > 0) {
    await User.findByIdAndUpdate(req.body.id, {
      full_name: req.body.full_name,
      description: req.body.description,
    });
    res.redirect("/myblogs/" + req.user._id);
  } else {
    res.redirect(`/edit_profile/${req.user._id}?error=1`);
  }
};

module.exports = {
  deleteUser,
  editUser,
};
