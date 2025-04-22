CREATE TABLE IF NOT EXISTS events (
                                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                                      title TEXT NOT NULL,
                                      description TEXT,
                                      location TEXT,
                                      date TEXT,
                                      image TEXT
);
