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
const flash = require('connect-flash');
const FacebookStrategy = require('passport-facebook').Strategy;

/**
 *  App Configuration
 */
app.use(flash());
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
    googleId: String,
    facebookId: String,
    secret: String
});
//add plugins
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create user model
const User = mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
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
        //console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:9090/auth/facebook/callback"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
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
    //console.log(typeof(req.flash("error")));
    res.render("login", { message: req.flash("error") });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", async (req, res) => {
    await User.find({ "secret": { $ne: null } },
        (err, foundUsers) => {
            if (err) console.log(foundUsers, err);
            else {
                if (foundUsers) res.render("secrets", { usersWithSecrets: foundUsers });
            }
        });
});

app.get("/submit", connectEnsureLogin.ensureLoggedIn(), (req, res) => {

    res.render("submit");

});
app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;

    if (req.isAuthenticated) {
        User.findById(req.user.id, (err, foundUser) => {
            if (err) console.log(err);
            else {
                if (foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(() => {
                        res.redirect("/secrets");
                    });

                }
            }
        });
    }
    else redirect("/login");
});
app.post("/register", (req, res) => {
    User.register({ username: req.body.username },
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
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/callback",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });


app.post("/login",
    passport.authenticate("local", {
        successRedirect: "/secrets",
        failureRedirect: "/login",
        failureFlash: true //"invalid username or password"
    })
);
// app.post('/login', function(req, res, next) {
//     passport.authenticate('local', function(err, user, info) {
//       if (err) { return next(err); }
//       if (!user) { return res.redirect('/login'); }
//       req.logIn(user, function(err) {
//         if (err) { return next(err); }
//         return res.redirect('/secrets');
//       });
//     })(req, res, next);
//   });

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.listen(port, () => {
    console.log("Listening for connections on port " + port);
});