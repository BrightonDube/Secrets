//jshint esversion: 8
require("dotenv").config();
//const md5 = require("md5") Don't use
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption"); don't use
const path = require("path");
const port = process.env.PORT;
const uri = process.env.DB_CONN;
const app = express();
// const encKey = process.env.SOME_32BYTE_BASE64_STRING;
// const sigKey = process.env.SOME_64BYTE_BASE64_STRING;
const bcrypt = require('bcrypt');//Recommended because of it's slowness.
const saltRounds = 10; //too many rounds will slow our app down

app.set("views", path.join(__dirname, "/views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "/public")));
//connect to mongoose
mongoose.connect(uri, {
    useNewUrlParser: true,
    useFindAndModify: false,
    useCreateIndex: true,
    useUnifiedTopology: true
}, (err) => {
    if (!err) console.log("Successfully connected to the database.");
    else console.log("Could not connect to the database");
});
//create user Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        min: 8
    }
});
// userSchema.plugin(encrypt, {
//     encryptionKey: encKey,
//     signingKey: sigKey,
//     excludeFromEncryption: ['username']
//   });

// Create user model
const User = mongoose.model("User", userSchema);

app.get("/", (req, res) => {
    res.render("home", {});
});

app.get("/login", (req, res) => {
    res.render("login", {});
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {

    bcrypt.hash(req.body.password, saltRounds, async function (err, hash) {
        // Store hash in your password DB.
        const user = new User({
            username: req.body.username,
            password: hash
        });
        await user.save((err) => {
            if (err) {
                console.log(err);
                if (err.code === 11000) res.send("The user exists");
            } else res.render("secrets");
        });

    });

});

app.post("/login", async (req, res) => {
    await User.findOne({
        username: req.body.username
    }, (err, foundUser) => {
        if (!err) {
            if (!foundUser) res.send("invalid username or password");
            else {
                bcrypt.compare(req.body.password, foundUser.password, async (err, result) => {
                    if (result) res.render("secrets");
                    else res.send("Invalid username or password!");
                });

            }
        }
        else console.log(err);
    });


});

app.get("/logout", (req, res) => {
    res.redirect("/");
});

app.listen(port, () => {
    console.log("Listening for connections on port " + port);
});