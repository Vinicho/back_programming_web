
import mysql from 'mysql2';

export const pool = mysql.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '12345678',
    database: 'genepass'    
});

export const query = (sql, params) => {
    return new Promise((resolve, reject) => {
      pool.query(sql, params, (error, results) => {
        if (error) {
          reject(error);
        } else {
          resolve(results);
        }
      });
    });
  };


