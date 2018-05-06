import sqlite from 'sqlite';

const db = sqlite.open('./db/database.sqlite').then(db => {
  db.migrate({migrationsPath:'./db/migrate/'})
});
