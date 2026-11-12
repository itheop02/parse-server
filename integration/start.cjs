'use strict';
// Baseline host for the unmodified stable Parse Server source build.
const path = require('path');
const fs = require('fs');
const root = path.resolve(__dirname, '..');
const express = require(path.join(root, 'node_modules', 'express'));
const { ParseServer } = require(path.join(root, 'lib'));
(async () => {
  const port = Number(process.env.PORT || 1337);
  const api = new ParseServer({
    appId: 'privacy-integration-local',
    masterKey: process.env.PARSE_MASTER_KEY || fs.readFileSync(process.env.BASELINE_SECRET_FILE, 'utf8'),
    databaseURI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/privacy-integration',
    serverURL: 'http://127.0.0.1:' + port + '/parse',
    appName: 'Local integration baseline',
    allowClientClassCreation: false,
    verifyUserEmails: false,
  });
  console.log('Starting Parse database initialization');
  await api.start();
  console.log('Parse initialized');
  const app = express();
  app.use('/parse', api.app);
  console.log('Starting PrivacyLib adapter');
  const gdpr = await require('./gdpr.route')({ serverURL: 'http://127.0.0.1:' + port + '/parse', appId: 'privacy-integration-local', databaseURI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/privacy-integration' });
  app.use('/gdpr', gdpr.router);
  const server = app.listen(port, '127.0.0.1', () => console.log('Parse baseline ready at http://127.0.0.1:' + port + '/parse'));
  async function stop() { server.close(); await gdpr.close(); await api.handleShutdown(); process.exit(0); }
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
})().catch(error => { console.error(error.message); process.exit(1); });
