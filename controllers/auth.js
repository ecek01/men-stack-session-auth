const express = require("express");
const router = express.Router();
const User = require("../models/user.js");
const bcrypt = require("bcrypt");

module.exports = router;

// Render sign-up form
router.get("/sign-up", (req, res) => {
  res.render("auth/sign-up.ejs");
});

// Render sign-in form
router.get("/sign-in", (req, res) => {
  res.render("auth/sign-in.ejs");
});

// Handle sign-up
router.post("/sign-up", async (req, res) => {
  try {
    const userInDatabase = await User.findOne({ username: req.body.username });
    if (userInDatabase) {
      return res.send("Username already taken.");
    }

    if (req.body.password !== req.body.confirmPassword) {
      return res.send("Password and Confirm Password must match");
    }

    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    req.body.password = hashedPassword;

    const user = await User.create(req.body);
    res.send(`Thanks for signing up ${user.username}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred during sign-up.");
  }
});

// Handle sign-in
router.post("/sign-in", async (req, res) => {
  try {
    const userInDatabase = await User.findOne({ username: req.body.username });
    if (!userInDatabase) {
      return res.send("Login failed. Please try again.");
    }

    const validPassword = bcrypt.compareSync(
      req.body.password,
      userInDatabase.password
    );
    if (!validPassword) {
      return res.send("Login failed. Please try again.");
    }

    req.session.user = {
      username: userInDatabase.username,
      _id: userInDatabase._id,
    };

    // Redirect after successful login
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred during sign-in.");
  }
});

// Handle sign-out
router.get("/sign-out", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});
