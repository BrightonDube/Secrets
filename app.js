//jshint esversion: 8
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const port = process.env.PORT;
const uri = process.env.DB_CONN;
const app = express();
const errorHandler = require('strong-error-handler');
const isProduction = process.env.NODE_ENV === 'production';
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require('mongoose-findorcreate');

/**
 *  App Configuration
 */
app.use(session({
    secret: process.env.SECRET,
    cookie: { maxAge: 60000 },
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.set("views", path.join(__dirname, "/views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "/public")));
if (!isProduction) {
    app.use(errorHandler());
}

//connect to mongoose
mongoose.connect(uri, {
    useNewUrlParser: true,
    useFindAndModify: false,
    useCreateIndex: true,
    useUnifiedTopology: true
}, (err) => {
    if (!err) console.log("Successfully connected to the database.");
    else console.log("Could not connect to the database").errorHandler();
});
//create user Schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String

});
//add passportLocalMongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create user model
const User = mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
//Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:9090/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));
//ROUTES
const connectEnsureLogin = require('connect-ensure-login');
app.get("/", (req, res) => {
    res.render("home");

});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", connectEnsureLogin.ensureLoggedIn(), (req, res) => {
    res.render("secrets");
});
app.get("/submit", connectEnsureLogin.ensureLoggedIn(), (req, res) => {

    res.render("submit");

});
app.post("/submit", connectEnsureLogin.ensureLoggedIn, (req, res) => {
    res.render("secrets"/*, secret : secrets*/);
});
app.post("/register", async (req, res) => {
    await User.register({ username: req.body.username },
        req.body.password, (err, user) => {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                });
            }
        });
    // bcrypt.hash(req.body.password, saltRounds, async function (err, hash) {
    //     // Store hash in your password DB.
    //     const user = new User({
    //         username: req.body.username,
    //         password: hash
    //     });
    //     await user.save((err) => {
    //         if (err) {
    //             console.log(err);
    //             if (err.code === 11000) res.send("The user exists");
    //         } else res.render("secrets");
    //     });

    // });

});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.render("secrets");
  });

app.post("/login", async (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            errorHandler(err);
            res.redirect("/login");
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });

    // await User.findOne({
    //     username: req.body.username
    // }, (err, foundUser) => {
    //     if (!err) {
    //         if (!foundUser) res.send("invalid username or password");
    //         else {
    //             bcrypt.compare(req.body.password, foundUser.password, async (err, result) => {
    //                 if (result) res.render("secrets");
    //                 else res.send("Invalid username or password!");
    //             });

    //         }
    //     }
    //     else console.log(err);
    // });


});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.listen(port, () => {
    console.log("Listening for connections on port " + port);
});