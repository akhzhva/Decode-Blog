const express = require("express");
const router = express.Router();
const User = require("../auth/User");
const Category = require("../Category/Category");
const Blog = require("../Blogs/blog");
const Comment = require("../Comments/Comment");

router.get("/", async (req, res) => {
  const options = {};
  const selectedCategory = await Category.findOne({ key: req.query.categ });
  if (selectedCategory) {
    options.category = selectedCategory._id;
  }

  let page = 0;
  const limit = 4;
  if (req.query.page && req.query.page > 0) {
    page = parseInt(req.query.page, 10) - 1;
  }

  if (req.query.search && req.query.search.length > 0) {
    options.$or = [
      {
        title: new RegExp(req.query.search, "i"),
      },
      {
        description: new RegExp(req.query.search, "i"),
      },
    ];
    res.locals.search = req.query.search;
  }

  const totalBlogs = await Blog.countDocuments(options);
  const allCategories = await Category.find();
  const blogs = await Blog.find(options)
    .limit(limit)
    .skip(page * limit)
    .populate("user")
    .populate("category");

  const blogsWithComments = await Promise.all(
    blogs.map(async (blog) => {
      const commentCount = await Comment.countDocuments({ blogID: blog._id });
      return { ...blog.toObject(), commentCount };
    })
  );

  res.render("index", {
    user: req.user ? req.user : {},
    categories: allCategories,
    loginUser: req.user,
    blogs: blogsWithComments,
    pages: Math.ceil(totalBlogs / limit),
    currentPage: page + 1,
    selectedCategory: selectedCategory ? selectedCategory.key : null,
    search: req.query.search || "",
  });
});

router.get("/myblogs/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    let page = 0;
    const limit = 4;
    if (req.query.page && req.query.page > 0) {
      page = parseInt(req.query.page, 10) - 1;
    }

    const options = {};
    if (req.query.search && req.query.search.length > 0) {
      options.$or = [
        { title: new RegExp(req.query.search, "i") },
        { description: new RegExp(req.query.search, "i") },
      ];
      res.locals.search = req.query.search;
    }

    const totalBlogs = await Blog.countDocuments({
      user: req.params.id,
      ...options,
    });
    const blogs = await Blog.find({ user: req.params.id, ...options })
      .limit(limit)
      .skip(page * limit)
      .populate("user")
      .populate("category");

    const blogsWithComments = await Promise.all(
      blogs.map(async (blog) => {
        const commentCount = await Comment.countDocuments({ blogID: blog._id });
        return { ...blog.toObject(), commentCount };
      })
    );

    const commentCount = await Comment.countDocuments({ authorID: user._id });

    if (user) {
      res.render("myblogs", {
        user: user,
        loginUser: req.user,
        blogs: blogsWithComments,
        pages: Math.ceil(totalBlogs / limit),
        currentPage: page + 1,
        search: req.query.search || "",
        commentCount: commentCount,
      });
    } else {
      res.redirect("/not_found");
    }
  } catch (error) {
    res.redirect("/not_found");
  }
});

router.get("/not_found", (req, res) => {
  res.render("notFound", {
    user: req.user ? req.user : {},
    loginUser: req.user,
  });
});

router.get("/auth", (req, res) => {
  res.render("authorization", {
    user: req.user ? req.user : {},
    loginUser: req.user,
  });
});

router.get("/reg", (req, res) => {
  res.render("registration", {
    user: req.user ? req.user : {},
    loginUser: req.user,
  });
});

router.get("/post/:id", async (req, res) => {
  try {
    const comments = await Comment.find({ blogID: req.params.id }).populate(
      "authorID"
    );
    const blogId = req.params.id;
    const blog = await Blog.findById(blogId)
      .populate("user")
      .populate("category");
    const allCategories = await Category.find();

    if (blog) {
      res.render("post", {
        user: req.user ? req.user : {},
        loginUser: req.user,
        categories: allCategories,
        blog,
        comments,
      });
    } else {
      res.redirect("/not_found");
    }
  } catch (error) {
    res.redirect("/not_found");
  }
});

router.get("/new", async (req, res) => {
  const allCategories = await Category.find();
  res.render("new_post", {
    user: req.user ? req.user : {},
    categories: allCategories,
    loginUser: req.user,
  });
});

router.get("/edit/:id", async (req, res) => {
  try {
    const blogId = req.params.id;
    const blog = await Blog.findById(blogId)
      .populate("user")
      .populate("category");
    const allCategories = await Category.find();
    if (blog) {
      res.render("edit_post", {
        user: req.user ? req.user : {},
        loginUser: req.user,
        categories: allCategories,
        blog,
      });
    } else {
      res.redirect("/not_found");
    }
  } catch (error) {
    res.redirect("/not_found");
  }
});

router.get("/edit_profile/:id", async (req, res) => {
  try {
    res.render("edit_profile", {
      user: req.user ? req.user : {},
      loginUser: req.user,
    });
  } catch (error) {
    res.redirect("/not_found");
  }
});

module.exports = router;
