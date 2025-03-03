import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local"
import GoogleStrategy from "passport-google-oauth20";
import axios from "axios";


const app = express();
const port = 3000;
const saltRounds = 10;

env.config(); // Load environment variables

const db = new pg.Client({ // Create a new instance of the pg client
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});

db.connect(); // Connect to the database

// Middleware setup for express
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Middleware setup for session
app.use(session({                       // Each session is stored in the RAM of the server
    secret: process.env.SESSION_SECRET, // Session secret key 
    resave: false,                      // Save session even if not modified 
    saveUninitialized: true,            // Save session even if not initialized 
    cookie:{
        maxAge: 6 * 60 * 60 * 1000, // 6 hours,
        httpOnly: true,             // Cookie cannot be accessed by client side scripts 
        secure: false,              // Only send cookie over https
    }
}));

// Middleware setup for passport
app.use(passport.initialize());
app.use(passport.session());

// Middleware to check if the user is authenticated, this is available in all EJS templates
app.use((req, res, next) => { 
    res.locals.userAuthenticated = req.isAuthenticated(); 
    next(); // Move to the next middleware
});

// Define passport strategy for local authentication
passport.use("local", new Strategy(async function verify(username, password, done){
    try{
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
        if(result.rows.length > 0){ // if user is found
            const user = result.rows[0];
            if(user.auth_method === "google"){
                return done(null, false, {message: "This email is registred with Google. Please login using Google!"});
            }else{
                const storedHashedPassword = user.password;
                bcrypt.compare(password, storedHashedPassword, (err, valid) =>{
                    if(err){ 
                        console.log("Error comparing password: ", err);
                        return done(err);
                    }else{ 
                        if(valid){ // if password is correct
                            return done(null, user); 
                        }else{
                            return done(null, false, {message: "Incorrect password. Please try again!"});
                        }
                    }
                });
            }
        }else{
            return done(null, false, {message: "Incorrect email. Please try again!"});
        }
    }catch(err){
        console.log(err);
        return done(err);
    }
}));

// Define passport strategy for Google authentication
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
}, async(accessToken, refreshToken, profile, done) =>{
    console.log("Logged in user: ", profile.emails[0].value);
    try{
        const email = profile.emails[0].value;
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if(result.rows.length === 0){ // If user is not found, create a new user
            const newUser = await db.query(
                "INSERT into users (email, google_id, auth_method) VALUES ($1, $2, $3) RETURNING *",
                [email, profile.id, "google"]);
            done(null, newUser.rows[0]);
        }else{  // If user is found, return the user
            done(null, result.rows[0]);
        }
    }catch(err){
        console.log("Error in Google strategy: ", err);
        return done(err);
    }
}));


passport.serializeUser((user, done) =>{  // When a user logs in, only their id is stored in the session to keep it lightweight
    done(null, user.id);
});

passport.deserializeUser(async(id, done) =>{ // When a user makes a request, the user's id is used to retrieve their information from the database
    try{
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        const user = result.rows[0];
        done(null, user);
    }catch(err){
        console.log(err);
        done(err, null);
    }
});

app.get("/", (req, res) =>{
    res.render("home.ejs");
});

app.get("/register", (req, res) =>{
    res.render("register.ejs", { errorMessage: ""});
});

// Route that initiates Google authentication
app.get("/auth/google", passport.authenticate("google",{
    scope: ["profile", "email"]
}));

// The callback for Google after the user logs in
app.get("/auth/google/myBooks", passport.authenticate("google",{
    successRedirect: "/myBooks",
    failureRedirect: "/login",
}));

app.get("/login", (req, res) =>{
    res.render("login.ejs", { error: ""});
});

// Register using email and password, where password is encrypted using bcrypt
app.post("/register", async(req, res) =>{
    const username = req.body.username;
    const password = req.body.password;
    try{
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [username]); // check if email already exists
  
      if (checkResult.rows.length > 0){ 
          if (checkResult.rows[0].auth_method === "google") {
              return res.render("register.ejs", { errorMessage: "This email is registered with Google. Please log in using Google." });
          }
          res.render("register.ejs", {errorMessage: "Email already exists!"});
      }else{
          bcrypt.hash(password, saltRounds, async function(err, hash){ // encrypt password and store in the database the hash value for the password
              if(err){
                  console.log("Error hashing password: ", err);
              }else{
                 await db.query("INSERT INTO users (email, password, auth_method) VALUES ($1, $2, $3)", [username, hash, "local"]);
                 res.redirect("/login");
              }
          });
      }
    }catch(err){
      console.log(err);
      res.render("register.ejs", {errorMessage:"Please try again!"});
    }
  });
  
  // Login using email and password
  app.post("/login", (req, res, next) => {
      passport.authenticate("local", (err, user, info) => {
          if (err) {
              return next(err);
          }
          if (!user) { // If user is not found
              return res.render("login.ejs", { error: info.message});
          }
          req.logIn(user, (err) => {
              if (err) {
                  return next(err);
              }
              console.log("Logged in user: ", user.email);
              return res.redirect("/myBooks");
          });
   })(req, res, next);
  });

app.listen(port, () =>{
    console.log(`Server is running on port ${port}`);
});