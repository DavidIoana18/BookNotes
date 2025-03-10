CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT,   -- NULL for the users authenticated through Google
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    google_id VARCHAR(255),  -- Google id for the users authenticated through Google
    auth_method TEXT NOT NULL
);

CREATE TABLE followers (
    id SERIAL PRIMARY KEY,
    follower_id INT REFERENCES users(id) ON DELETE CASCADE,
    followed_id INT REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (follower_id, followed_id) -- a user can't follow another user more than once
);

CREATE TABLE books (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    cover_url TEXT NOT NULL,
    rating INTEGER CHECK (rating BETWEEN 1 AND 5) NOT NULL, -- check constraint to ensure the rating is between 1 and 5
    review TEXT,
    genre VARCHAR(255) NOT NULL
);