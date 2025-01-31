const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

// Middleware
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "This is our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Database Connection
mongoose.connect("mongodb://localhost:27017/secretsDB", { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
    username: String, // Use username instead of email for authentication
    password: String,
    secrets: [String] // Store multiple secrets as an array
});

// Plugin for password hashing & authentication
userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Home Route
app.get("/", function (req, res) {
    res.render("home");
});

// Register Route
app.get("/register", function (req, res) {
    res.render("register");
});

app.post("/register", async function (req, res) {
    try {
        const user = await User.register({ username: req.body.username }, req.body.password);
        passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets"); // Redirect to secrets page after successful registration
        });
    } catch (err) {
        console.log(err);
        res.redirect("/register");
    }
});

// Login Route
app.get("/login", function (req, res) {
    res.render("login");
});

app.post("/login", async function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
            res.redirect("/login"); // Stay on login page if there's an error
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets"); // Redirect to secrets page after successful login
            });
        }
    });
});

// Secrets Route - Show only logged-in user's secrets
app.get("/secrets", async function (req, res) {
    if (req.isAuthenticated()) {
        try {
            const loggedInUser = await User.findById(req.user._id);
            res.render("secrets", { secrets: loggedInUser.secrets || [] });
        } catch (err) {
            console.log(err);
            res.redirect("/login");
        }
    } else {
        res.redirect("/login");
    }
});

// Submit Secret Route
app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", async function (req, res) {
    if (req.isAuthenticated()) {
        try {
            const foundUser = await User.findById(req.user._id);
            if (foundUser) {
                foundUser.secrets.push(req.body.secret);
                await foundUser.save();
                res.redirect("/secrets");
            }
        } catch (err) {
            console.log(err);
            res.redirect("/submit");
        }
    } else {
        res.redirect("/login");
    }
});

// Logout Route
app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        }
        res.redirect("/");
    });
});

// Server Start
app.listen(5000, function () {
    console.log("Server started on port 5000.");
});
