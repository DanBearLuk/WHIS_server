require('dotenv').config();

const Config = {
    CLIENT_URL: 3000,
    API_URL: 2700,
    DatabaseInfo: {
        USERNAME: 'Admin',
        PASSWORD: encodeURIComponent('12345squared'),
        URI: 'whiscluster.ahtfr8p.mongodb.net/'
    }
};

module.exports = { default: Config };