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

app.get("/searchCover", (req, res) =>{
    res.render("searchCover.ejs");
});

app.get("/addBook", (req, res) =>{
    const title = req.session.searchTitle;
    const coverUrl = req.session.coverUrl || "/images/defaultCover.jpg";
    const messageToSend = req.session.message || "";

     // Delete the data from the session after using it
    //  req.session.title = null;
    //  req.session.coverUrl = null;
    //  req.session.message = null;

    res.render("addBook.ejs", {cover_url: coverUrl, message: messageToSend, searchTitle: title});
});

// Protected route
app.get("/myBooks", async (req, res) =>{
    if(req.isAuthenticated()){ //passport method to check if user is authenticated, returning true or false
        try{
            const result = await db.query("SELECT * FROM books WHERE user_id = $1 ORDER BY id ASC", [req.user.id]);
            // console.log("Books: ", result.rows);
            res.render("myBooks.ejs", {books: result.rows});
        }catch(err){
            console.log(err);
        }       
    }else{
        res.redirect("/login");
    }
});

app.get("/bookDetails/:id", async(req, res) =>{
    const bookId = req.params.id;
    try{
        const result = await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
        if(result.rows.length === 0){
            return res.redirect("/myBooks");
        }else{
             const book = result.rows[0];
             res.render("bookDetails.ejs", {book: book});
        }
       
    }catch(err){
        console.log("Error fetching book details: ", err);
        res.redirect("/myBooks");
    }
});

app.get("/filterBooks", async(req, res) =>{
    // because the form that sends the request is a GET form, the data is sent in the URL( => query parameters)
    const sortByTitle = req.query.sortByTitle || null;
    const sortByRating = req.query.sortByRating || null;
    const sortByGenre = req.query.sortByGenre || null;

    let whereClauses=["user_id = $1"];
    let values = [req.user.id];
    let orderByClauses = [];
    
    if(sortByGenre){
       whereClauses.push(`genre = $${values.length + 1}`); // tipically genre = $2 but if sortbyGenre is null, then $2 will never be used and the query will fail, SO i use the incrementation 
       values.push(sortByGenre);
    }
    if(sortByTitle){
        orderByClauses.push(`title ${sortByTitle}`);  // title ASC or title DESC
    }
    if(sortByRating){
        orderByClauses.push(`rating ${sortByRating}`); // rating ASC or rating DESC
    }
    if (orderByClauses.length === 0) {
        orderByClauses.push("id ASC");
    }
    let query = `SELECT * FROM books WHERE ${whereClauses.join(" AND ")} 
                ${orderByClauses.length ? "ORDER BY " + orderByClauses.join(", ") : ""}`;

    try{
        const books = await db.query(query, values);
        res.render("myBooks.ejs", {books: books.rows});
    }catch(err){
        console.log("Error sorting books: ", err);
        res.redirect("/myBooks");
    }
});

app.get("/logout", (req, res) =>{
    req.logout((err) =>{ // Passport delete the user from the session
        if (err) return next(err);
        req.session.destroy(() =>{ // Delete the current session from the server
            console.log("Logged out user");
            res.redirect("/");
        });
    });
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


  app.post("/searchCover", async(req, res) =>{
    const title = req.body.title.trim().toLowerCase();
    let coverUrl = "";
    let messageToSend = "";

    try{
         //encode the title to make it URL safe in case the user enters special characters,
         // they are converted to a URL safe format
        const response = await axios.get(`https://openlibrary.org/search.json?title=${encodeURIComponent(title)}`);
        //console.log(response.data);
        const book = response.data.docs[0]; // Get the first book cover
        
        if(book && book.cover_edition_key){
            coverUrl = `https://covers.openlibrary.org/b/olid/${book.cover_edition_key}-M.jpg`;
        }else{
            coverUrl = "/images/defaultCover.jpg";
            messageToSend = "No book cover found";
        }

        // Save the book cover and the title in the session
        req.session.searchTitle = title;
        req.session.coverUrl = coverUrl;
        req.session.message = messageToSend;

        res.redirect("/addBook");
     }catch(err){
        console.error("Error fetching book covers:", err);
        req.session.searchTitle = title;
        req.session.coverUrl = "/images/defaultCover.jpg",
        req.session.message = "Error fetching book cover";
        res.redirect("/addBook");
    }
});

app.post("/addBook", async(req, res) =>{
    // Delete the data from the session after using it
    req.session.searchTitle = null;
    req.session.coverUrl = null;
    req.session.message = null;

    if(req.isAuthenticated()){
        let title = req.body.title;
        let author = req.body.author;
        const coverUrl = req.body.cover_url;
        const rating = req.body.rating;
        const review = req.body.review;
        const genre = req.body.genre;

        // Capitalize the first letter of each word in the title
        title = title.replace(/\b\w/g, char => char.toUpperCase()); // /b identify the beginning of a word, \w search the first character of the word, g means that the search is global, so it will search for all the words in the string
        author = author.replace(/\b\w/g, char => char.toUpperCase());
        
        if (!coverUrl) {
            return res.render("addBook", { 
                message: `Please select a cover for "${title}"`,
                cover_url: coverUrl, 
                searchTitle: title 
            });
        }

        if(!genre){
            return res.render("addBook", {
                message: `Please select a genre for "${title}"`,
                cover_url: coverUrl,
                searchTitle: title
            });
        }

        try{
            await db.query(
                "INSERT INTO books (user_id, title, author, cover_url, rating, review, genre) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                 [req.user.id, title, author, coverUrl, rating, review, genre]
            );
            res.redirect("/myBooks");
        }catch(err){
        console.log("Error adding book: ", err);
        res.redirect("/addBook");
        }
    }else{
        res.redirect("/login");
    }
});

app.listen(port, () =>{
    console.log(`Server is running on port ${port}`);
});