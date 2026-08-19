// Preload script to set env vars before any imports
process.env.FAM_SERVER_SECRET = 'test-secret-for-integration';
process.env.FAM_DB_PATH = ':memory:';
