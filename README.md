# BookHub - A Web Application for Book Lovers

# 📌 Project Overview

BookHub is a web application designed for book enthusiasts to manage their reading list, connect with other users and explore new books. Users can register, log in, add books they have read, edit or delete them, view other users' profiles and follow or unfollow other users. The application **supports both local authentication and Google OAuth** for a seamless login experience.

#### BookNotes provides an engaging way for book lovers to track their reading progress, explore books from other users and build a personalized reading community! 

# 🛠 Tech Stack

## **Backend**

- Node.js - JavaScript runtime for server-side development

- Express.js - Web framework for handling routes and middleware

- PostgreSQL - Relational database for storing users, followers and books data

- pg (node-postgres) - PostgreSQL client for Node.js

- bcrypt - Secure password hashing (user passwords are encrypted before being stored in the database)

- Passport.js - Authentication middleware (supports *local authentication* and *Google OAuth*)

- dotenv - Environment variable management

- EJS (Embedded JavaScript) - Templating engine for dynamic HTML rendering

- Axios - HTTP client used to fetch book covers from the [Open Library Covers API](https://openlibrary.org/dev/docs/api/covers) and book data from the [Open Library Search API](https://openlibrary.org/dev/docs/api/search)

## **Frontend**

- HTML - Structure for web pages

- CSS - Styling and layout management

- JavaScript - Dynamic client-side interactions

- EJS - Server-side rendering for dynamic content

# **🔥 Features**

### User Authentication

✔ Register and log in via email + password or Google OAuth

✔ Secure password storage using bcrypt

### Book Management

✔ Users can add books with title, author, rating, review, genre (selected from a predefined list) and cover image

✔ If the book cover is available via the **Open Library Covers API**, it is fetched automatically using Axios. If no cover is found, a default image is used

✔ Books can be sorted:

- By title (ascending/descending)
- By rating (ascending/descending)
- By genre

✔ Users can view book details, including their review and rating

✔ Users can see other readers who have read the same book

✔ Users can edit the rating and review they have given to a book

✔ Users can delete a book from their list

### User Interactions

✔ Follow and unfollow other users

✔ View lists of followers and following

✔ Access other users' profiles to see their book lists and reviews

✔ Sort books on other users' profiles by title, rating or genre

### User Profile

✔ Displays user's name, email, number of books read, number of followers and number of users followed

✔ Users can delete their account

# Responsive Design

✔ Optimized for desktop, tablet and mobile (media queries for max-width: 1024px, max-width: 768px and max-width: 480px)

# Database Schema

BookHub uses a PostgreSQL database with the following tables:

- Users Table (users): Stores user information.

- Followers Table (followers): Stores follow relationships between users.

- Books Table (books): Stores information about books added by users.
#
© 2025 David Ioana. All rights reserved.

# Demo:
![demo.gif](https://github.com/DavidIoana18/BookNotes/blob/main/demo/demo.gif)
