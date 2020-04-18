//jshint esversion: 8
require("dotenv").config();
const md5 = require("md5")
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const path = require("path");
const port = process.env.PORT;
const uri = process.env.DB_CONN;
const app = express();
// const encKey = process.env.SOME_32BYTE_BASE64_STRING;
// const sigKey = process.env.SOME_64BYTE_BASE64_STRING;
console.log(md5("cjd8XMsNDw@94F7NnYT!WJwbpIxOpZ"))

app.set("views", path.join(__dirname,"/views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({extended:false}));
app.use(express.static(path.join(__dirname, "/public")));
//connect to mongoose
mongoose.connect(uri, {
    useNewUrlParser: true,
    useFindAndModify: false,
    useCreateIndex: true,
    useUnifiedTopology: true
}, (err)=>{
    if(!err) console.log("Successfully connected to the database.");
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

app.get("/", (req, res)=>{
    res.render("home", {});
});

app.get("/login", (req, res)=>{
    res.render("login", {});
});

app.get("/register", (req, res)=>{
    res.render("register");
});

app.post("/register", async (req, res)=>{
    const user = new User({
        username: req.body.username,
        password: md5(req.body.password)
    });
    await user.save((err)=>{
        if(err) {
            console.log(err);
            if(err.code === 11000) res.send("The user exists");
        }else res.render("secrets");
    });
});

app.post("/login", async(req, res)=>{
    await User.findOne({
        username: req.body.username       
        }, (err, foundUser)=>{
            if(!err){            
            if(!foundUser) res.send("no user found with that email");
            else if (foundUser.password === md5(req.body.password)) res.render("secrets");
                 else res.send("You entered a wrong password");
            }
            else console.log(err);
        });
});

app.get("/logout", (req, res)=>{
    res.redirect("/");
});

app.listen(port, ()=>{
    console.log("Listening for connections on port " + port);
});