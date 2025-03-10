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
    // console.log("Profile: ", profile);
    try{
        const email = profile.emails[0].value;
        if (!email) return done(null, false, { message: "No email associated with Google account." });
        const firstName = profile.name.givenName;
        const lastName = profile.name.familyName;

        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if(result.rows.length === 0){ // If user is not found, create a new user
            const newUser = await db.query(
                "INSERT into users (email, first_name, last_name, google_id, auth_method) VALUES ($1, $2, $3, $4, $5) RETURNING *",
                [email, firstName, lastName,  profile.id, "google"]);
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
app.get("/auth/google/user/books", passport.authenticate("google",{
    successRedirect: "/user/books",
    failureRedirect: "/login",
}));

app.get("/login", (req, res) =>{
    res.render("login.ejs", { error: ""});
});

app.get("/user/profile", async(req, res) =>{
    if(req.isAuthenticated()){
        try{
            const userDetails = await db.query("SELECT first_name, last_name, email FROM users WHERE id = $1", [req.user.id]);
            // Count the number of books read
            const booksReadNumber = await db.query("SELECT COUNT(*) FROM books WHERE user_id = $1", [req.user.id]);
            // Count the number of followers
            const followersNumber = await db.query("SELECT COUNT(*) FROM followers WHERE followed_id = $1",[req.user.id]); 
            // console.log("Followers: ", followersNumber);
            // Count the number of users the user is following
            const followedNumber = await db.query("SELECT COUNT(*) FROM followers WHERE follower_id = $1", [req.user.id]);
            // Get the list of followers
            const followersList = await db.query(
                `SELECT u.id, u.first_name, u.last_name,
                 CASE 
                    WHEN f2.follower_id IS NOT NULL THEN true 
                    ELSE false 
                 END AS followed 
                 FROM users u
                 JOIN followers f ON u.id = f.follower_id
                 LEFT JOIN followers f2 ON f2.followed_id = u.id AND f2.follower_id = $1
                 WHERE f.followed_id = $1`,
                 [req.user.id]);
           
            // Get the list of users the user is following
            const followedList = await db.query(
                `SELECT u.id, u.first_name, u.last_name,
                    TRUE AS followed
                FROM users u 
                INNER JOIN followers f ON u.id = f.followed_id 
                WHERE f.follower_id = $1`
                , [req.user.id]);

            res.render("profile.ejs", {
                user: userDetails.rows[0],
                currentUserId: req.user.id,
                booksReadCount: booksReadNumber.rows[0].count,
                followersCount: followersNumber.rows[0].count,
                followedCount: followedNumber.rows[0].count,
                followers: followersList.rows,
                followed: followedList.rows
            });

        }catch(err){
            console.log("ERROR fetching user details: ", err);
            res.redirect("/login");
        }
    }else{
        res.redirect("/login");
    }
});

app.get("/follower/books/:id", async(req, res) =>{
    const userId = req.params.id;
    let genresReadByUser = [];

    try{
        const books = await db.query("SELECT * FROM books WHERE user_id = $1", [userId]);
        const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
        
        const userGenresResult = await db.query("SELECT DISTINCT genre FROM books WHERE user_id = $1", [userId]);
        userGenresResult.rows.forEach(row =>{
            genresReadByUser.push(row.genre);
        });

        res.render("followerBooks.ejs", {
            books: books.rows, 
            user: user.rows[0],
            booksGenres: genresReadByUser
        });
        
    }catch(err){
        console.log("Error fetching follower books: ", err);
        res.redirect("/user/profile");
    }
});

app.get("/follower/bookDetails/:bookId/:userId", async(req, res) =>{
    const bookId = req.params.bookId;
    const userId = req.params.userId;
    try{
        const result = await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
        if(result.rows.length === 0){
            return res.redirect(`/follower/books/:${userId}`)
        }else{
            const book = result.rows[0];
            res.render("followerBookDetails.ejs", {book: book, userId: userId});
        }
    }catch(err){
        console.log("Error fetching book details: ", err);
        res.redirect("/user/profile");
    }
});

app.get("/user/searchBookCover", (req, res) =>{
    res.render("searchCover.ejs");
});

app.get("/user/addBook", (req, res) =>{
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
app.get("/user/books", async (req, res) =>{
    if(req.isAuthenticated()){ //passport method to check if user is authenticated, returning true or false
        let genresReadByUser = [];
        try{
            const result = await db.query("SELECT * FROM books WHERE user_id = $1 ORDER BY id ASC", [req.user.id]);
            // console.log("Books: ", result.rows);
            const userGenresResult = await db.query("SELECT DISTINCT genre FROM books WHERE user_id = $1", [req.user.id]);
            userGenresResult.rows.forEach(row =>{
            genresReadByUser.push(row.genre);
        });
            res.render("userBooks.ejs", {
                books: result.rows, 
                firstName:req.user.first_name,
                booksGenres: genresReadByUser
            });
        }catch(err){
            console.log("Error fetching user books: ", err);
        }       
    }else{
        res.redirect("/login");
    }
});

app.get("/user/bookDetails/:id", async(req, res) =>{
    const bookId = req.params.id;
    try{
        const result = await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
        if(result.rows.length === 0){
            return res.redirect("/user/books");
        }

        const book = result.rows[0];
        
        // Adds a boolean column `followed` to the result, which is true if the logged in user follows the other user, otherwise false. 
        // Left joins the `followers` table with alias `f` to check if the logged in user follows the other user.
        // I use the LEFT JOIN because I want to include all the users who read the book, even if the logged in user does not follow them.
        // Filters the results to include only users who have readed a book with the specified title and are not the logged in user.
        const usersResult = await db.query(`
            SELECT u.id, u.first_name, u.last_name, 
                   CASE WHEN f.follower_id IS NOT NULL THEN true ELSE false END AS followed 
            FROM users u
            JOIN books b ON u.id = b.user_id 
            LEFT JOIN followers f ON f.followed_id = u.id AND f.follower_id = $2
            WHERE b.title = $1 AND u.id != $2`,
            [book.title, req.user.id]);

        const usersWhoRead = usersResult.rows;
      
        res.render("userBookDetails.ejs", {
            book: book,
            usersWhoRead: usersWhoRead,
            currentUserId: req.user.id        
        });      
    }catch(err){
        console.log("Error fetching book details: ", err);
        res.redirect("/user/books");
    }
});

app.get("/user/editBook/:id", async(req, res) =>{
    const bookId = req.params.id;
    try{
        const result = await db.query("SELECT * FROM books WHERE id = $1", [bookId]);
        if(result.rows.length > 0){ // If book is found
            const book = result.rows[0];
            res.render("editBook.ejs", {book: book});
        }else{
            console.log("Book not found");
            res.redirect("/user/books");
        }
    }catch(err){
        console.log("Error fetching book: ", err);
        res.redirect("/user/books");
    }
});

app.post("/user/follow", async(req, res) =>{
    const followerId = req.body.follower_id;
    const followedId = req.body.followed_id;

    /* If the follow button is clicked from the book details page, 
    the book_id is sent in the request, otherwise it is sent from the profile page */
    const bookId = req.body.book_id || null;

    try{
        const checkFollow = await db.query(
        "SELECT * FROM followers WHERE follower_id = $1 AND followed_id = $2",
         [followerId, followedId]
        );
        
        if (checkFollow.rows.length > 0){ // If the logged in user is already following the other user -> unfollow button in EJS
            await db.query("DELETE FROM followers WHERE follower_id = $1 AND followed_id = $2", [followerId, followedId]);
        }else{ // If the logged in user is not following the other user -> follow button in EJS
            await db.query("INSERT INTO followers (follower_id, followed_id) VALUES ($1, $2)", [followerId, followedId]);
        }
        if(bookId){
            res.redirect(`/user/bookDetails/${bookId}`);
        }else{
            res.redirect("/user/profile");
        }
       
    }catch(err){
        console.log("Error following/unfollowing user: ", err);
        if(bookId){
            res.redirect(`/user/bookDetails/${bookId}`);
        }else{
            res.redirect("/user/profile");
        }
    }
});

app.get("/filterBooks", async(req, res) =>{
    // because the form that sends the request is a GET form, the data is sent in the URL( => query parameters)
    const sortByTitle = req.query.sortByTitle || null;
    const sortByRating = req.query.sortByRating || null;
    const sortByGenre = req.query.sortByGenre || null;
    const userId = req.query.userId || req.user.id; // if userId is provided that means that the filter is for the follower books, otherwise it is for the user books

    let whereClauses=["user_id = $1"];
    let values = [userId];
    let orderByClauses = [];
    let genresReadByUser = [];
    
    // If sort by genre is provided
    if(sortByGenre){
        whereClauses.push(`genre = $${values.length + 1}`); // tipically genre = $2 but if sortbyGenre is null, then $2 will never be used and the query will fail, SO i use the incrementation 
        values.push(sortByGenre);
     }

    // If sort by title is requested
    if(sortByTitle){
        orderByClauses.push(`title ${sortByTitle}`);  // title ASC or title DESC
    }

    // If sort by rating is requested
    if(sortByRating){
        orderByClauses.push(`rating ${sortByRating}`); // rating ASC or rating DESC
    }

    // Default sorting if no sort option is provided
    if (orderByClauses.length === 0) {
        orderByClauses.push("id ASC");
    }

    let query = `SELECT * FROM books WHERE ${whereClauses.join(" AND ")} 
                ${orderByClauses.length ? "ORDER BY " + orderByClauses.join(", ") : ""}`;

    try{
        const books = await db.query(query, values);
        const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
    
        const userGenresResult = await db.query("SELECT DISTINCT genre FROM books WHERE user_id = $1", [userId]);
        userGenresResult.rows.forEach(row =>{
            genresReadByUser.push(row.genre);
        });

        if(req.query.userId){
            res.render("followerBooks.ejs", 
                {books: books.rows, 
                user: user.rows[0],
                booksGenres: genresReadByUser
            });
        }else{
            res.render("userBooks.ejs", {
                books: books.rows, 
                firstName: req.user.first_name,
                booksGenres: genresReadByUser
            });
        }
    }catch(err){
        console.log("Error sorting books: ", err);
        if(req.query.userId){
            res.redirect(`/follower/books/:${userId}`);
        }else{
            res.redirect("/user/books");
        }
    }
});

app.get("/logout", (req, res, next) =>{
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
    const firstName = req.body.first_name;
    const lastName = req.body.last_name;
   
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
                 await db.query("INSERT INTO users (email, password, first_name, last_name, auth_method) VALUES ($1, $2, $3, $4, $5)", [username, hash, firstName, lastName, "local"]);
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
              return res.redirect("/user/books");
          });
   })(req, res, next);
  });


  app.post("/user/searchBookCover", async(req, res) =>{
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

        res.redirect("/user/addBook");
     }catch(err){
        console.error("Error fetching book covers:", err);
        req.session.searchTitle = title;
        req.session.coverUrl = "/images/defaultCover.jpg",
        req.session.message = "Error fetching book cover";
        res.redirect("/user/addBook");
    }
});

app.post("/user/addBook", async(req, res) =>{
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
            return res.render("addBook.ejs", { 
                message: `Please select a cover for "${title}"`,
                cover_url: coverUrl, 
                searchTitle: title 
            });
        }

        if(!genre){
            return res.render("addBook.ejs", {
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
            res.redirect("/user/books");
        }catch(err){
        console.log("Error adding book: ", err);
        res.redirect("/user/addBook");
        }
    }else{
        res.redirect("/login");
    }
});

app.post("/user/updateBook/:id", async(req, res) =>{
    if(req.isAuthenticated()){
        const bookId = req.params.id;
        const newRating = req.body.rating;
        const newReview = req.body.review;

        try{
            await db.query(
                "UPDATE books SET rating = $1, review = $2 WHERE id = $3 AND user_id = $4",
                 [newRating, newReview, bookId, req.user.id]
            );
            res.redirect("/user/books");
        }catch(err){
            console.log("Error updating book: ", err);
            res.redirect(`/user/editBook/${bookId}`);
        }
    }else{
        res.redirect("/login");
    }   
});

app.post("/user/deleteBook/:id", async(req, res) =>{
    if(req.isAuthenticated()){
        const bookId = req.params.id;
        try{
            await db.query(
                "DELETE FROM books WHERE id = $1 AND user_id = $2",
                 [bookId, req.user.id]
            );
            res.redirect("/user/books");
        }catch(err){
            console.log("Error deleting book: ", err);
            res.redirect(`/user/bookDetails/${bookId}`);
        }
    }else{
        res.redirect("/login");
    }
});

app.post("/user/deleteAccount", (req, res) => {
    if (req.isAuthenticated()) {
        const userId = req.user.id;

        // Distroy the session before deleting the account
        req.logout( async (err) => {
            if (err) {
                console.log("Error during logout: ", err);
                return res.redirect("/user/profile"); 
            }

            // After logout is successful, delete the user account
            try{
                await db.query("DELETE FROM users WHERE id = $1", [userId])
                console.log("User account deleted");
                res.redirect("/"); 
            }catch(err){
                console.log("Error deleting account: ", err);
                res.redirect("/user/profile");
            }       
        });
    } else {
        res.redirect("/login"); 
    }
});


app.listen(port, () =>{
    console.log(`Server is running on port ${port}`);
});