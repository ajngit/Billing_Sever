const sql = require('mssql');

const config = {
  user: 'admin',
  password: 'Adm!n001',
  server: 'mssql-191972-0.cloudclusters.net',
  database: 'HarvestHub',
  port: 10218,
  encrypt: true, // Always use encrypt for cloud deployments
  trustServerCertificate: true, // Skip certificate validation (optional)
  
  //connectionString: "Driver={ODBC Driver 18 for SQL Server};Server=LAPTOP-QAF46VQE;Database=HarvestHub;Trusted_Connection=yes;TrustServerCertificate=yes;"

};

module.exports = config;
