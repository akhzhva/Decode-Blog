const Category = require("./Category");

const getAllCategories = async (req, res) => {
  const data = await Category.find();
  res.status(200).send({ data });
};

module.exports = {
  getAllCategories,
};
