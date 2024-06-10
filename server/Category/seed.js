const Category = require("./Category");
const data = {
  "Прогнозы в IT": 0,
  "Веб-разработка": 1,
  "Мобильная разработка": 2,
  Фриланс: 3,
  Алгоритмы: 4,
  "Тестирование IT систем": 5,
  "Разработка игр": 6,
  "Дизайн и юзабилити": 7,
  "Искуственный интелект": 8,
  "Машинное обучение": 9,
};

async function writeDataCategory() {
  const length = await Category.countDocuments();
  if (length === 0) {
    const entries = Object.entries(data);
    for (const [name, key] of entries) {
      await new Category({
        name,
        key,
      }).save();
    }
  }
}

module.exports = writeDataCategory;
