const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimiter = require('express-rate-limit');
const Config = require('./config').default;
const jose = require('jose');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion } = require('mongodb');

const port = Config.API_URL;
const app = express();

const secret = new TextEncoder().encode('f30e7c6f861eb133858962c280d4388cf711a9a69697a72299ed9142d6c71dce');

const corsOptions = {
    origin: '*',
    credentials: true,
    optionsSuccessStatus: 200
};

const createLimiter = (period, amount) => rateLimiter({
    windowMs: period,
    max: amount,
    standardHeaders: true,
    legacyHeaders: false
});

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static('public', { maxAge: 31557600 }));

let mongoClient, usersCollection, counterCollection;

const initUsersDB = async () => {
  const DB = Config.DatabaseInfo;
  const uri = `mongodb+srv://${DB.USERNAME}:${DB.PASSWORD}@${DB.URI}`;

  mongoClient = new MongoClient(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverApi: ServerApiVersion.v1
  });
  await mongoClient.connect();

  usersCollection = mongoClient.db('whis').collection('users');
  counterCollection = mongoClient.db('whis').collection('counters');

  const cleanup = () => {
    mongoClient.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
};

initUsersDB();


async function createToken(id) {
  const alg = 'HS256';
  
  const jwt = await new jose.SignJWT({ id })
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('720h')
    .sign(secret);

  return jwt;
}


app.use('/api/users/createAccount', createLimiter(1  * 60 * 1000, 1));
app.post('/api/users/createAccount', async (req, res) => {
  if (!req.body) {
    return res.status(400).json({
      success: false,
      message: 'Body not found'
    });
  }

  const { username, password } = req.body;

  const check = await usersCollection.findOne({ username });

  if (check) {
    return res.status(409).json({ success: false });
  }

  const password_hash = await bcrypt.hash(password, 10);

  const counter = await counterCollection.findOneAndUpdate(
    { _id: 'users' }, 
    { $inc: { seq_value: 1 }}, 
    { returnDocument: 'after' }
  );

  const id = counter.value.seq_value;
  
  const jwt = await createToken(id);

  const result = await usersCollection.insertOne({
    _id: id,
    username,
    password: password_hash,
    savedList: []
  });

  res.cookie('token', jwt, { maxAge: 2592000000, httpOnly: true })
  return res.status(200).json({
    success: true,
    user: await usersCollection.findOne({ _id: result.insertedId })
  });
});


app.post('/api/users/login', async (req, res) => {
  const token = req.cookies.token;

  if (!token && !req.body && !req.body.username) {
    return res.status(400).json({
      success: false,
      message: 'Body not found'
    });
  }

  if (!req.body || !req.body.username) {
    try {
      const { payload } = await jose.jwtVerify(token, secret);

      if (payload.exp >= Date.now()) {
        res.clearCookie('token')
        return res.status(401).json({
          success: false,
          message: 'Unauthorized HTTP'
        });
      }

      const user = await usersCollection.findOne({ _id: payload.id });
      delete user.password
      
      const jwt = await createToken(user._id);
  
      res.cookie('token', jwt, { maxAge: 2592000000, httpOnly: true })
      return res.status(200).json({
        success: true,
        user
      });
    } catch {
      res.clearCookie('token')
      return res.status(401).json({
        success: false,
        message: 'Unauthorized HTTP'
      });
    }
  }

  const { username, password } = req.body;
  const user = await usersCollection.findOne({ username });

  if (!user || !await bcrypt.compare(password, user.password)) {
    res.clearCookie('token')
    return res.status(401).json({
      success: false,
      message: 'Unauthorized HTTP'
    });
  };

  const jwt = await createToken(user._id);

  delete user.password
  res.cookie('token', jwt, { maxAge: 2592000000, httpOnly: true })
  return res.status(200).json({
    success: true,
    user
  });
});


app.get('/api/users/deauthorize', async (req, res) => {
  return res.clearCookie('token').status(200).json({
    success: true
  });
});


app.post('/api/editList', async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized HTTP'
    });
  }

  if (!req.body || (!Array.isArray(req.body?.edit) && !Array.isArray(req.body?.remove))) {
    return res.status(400).json({
      success: false,
      message: 'Body not found'
    });
  }

  let payload;

  try {
    payload = (await jose.jwtVerify(token, secret)).payload;

    if (payload.exp >= Date.now()) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized HTTP'
      });
    }
  } catch {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized HTTP'
    });
  }

  let { savedList } = await usersCollection.findOne({ _id: payload.id });

  if (req.body.edit) {
    for (const { id, status, finishedAmount } of req.body.edit) {
      const result = savedList.find(el => el.id === id);
      
      if (result) {
        result.status = status;
        result.finishedAmount = finishedAmount;
      } else {
        savedList.push({
          id,
          status,
          finishedAmount
        });
      }
    }
  }

  if (req.body.remove) {
    savedList = savedList.filter(el => !req.body.remove.includes(el.id));
  }

  const result = await usersCollection.findOneAndUpdate(
    { _id: payload.id }, 
    { $set: { savedList }}, 
    { returnDocument: 'after' }
  );

  return res.status(200).json({
    success: true,
    user: {
      savedList: result.value.savedList
    }
  });
});


app.listen(port);
console.log('Started');
