CREATE TABLE rental_listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    price_year REAL NOT NULL,
    price_month REAL NOT NULL,
    marina TEXT NOT NULL,
    length INTEGER NOT NULL,
    width INTEGER NOT NULL,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    electricity TEXT NOT NULL,
    water TEXT NOT NULL,
    phone TEXT NOT NULL
);
