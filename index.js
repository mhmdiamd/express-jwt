import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
dotenv.config();

const app = express();

app.use(express.json());

const users = [
  {
    id: 1,
    username: 'ilham',
    password: 'password',
    isAdmin: true,
  },
  {
    id: 2,
    username: 'farhan',
    password: 'password',
    isAdmin: false,
  },
];

let refreshTokens = [];

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: user.isAdmin,
    },
    process.env.JWT,
    { expiresIn: '15m' }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.REFRESH_TOKEN);
};

app.post('/api/refresh', (req, res) => {
  // Take the refresh token from the user
  const refreshToken = req.body.token;

  // send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json('Unauthenticated!');
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json('Refresh token is not valid');
  }
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    // if everything is ok, create new access token, refresh token and send to user
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);
    res.status(200).json({
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    });
  });
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((user) => username == user.username && password == user.password);
  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    console.log(refreshToken);
    refreshTokens.push(refreshToken);

    const { password, ...others } = user;
    res.status(200).json({
      ...others,
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  } else {
    res.status(403).json({
      message: 'username or password Incorrect!',
    });
  }
});

const verify = (req, res, next) => {
  const getToken = req.headers.authorization;
  if (!getToken) {
    return res.status(401).json('You are Unauthenticate!');
  }
  const token = getToken.split(' ')[1];
  if (token) {
    jwt.verify(token, process.env.JWT, (err, user) => {
      if (err) {
        res.status(403).json({
          message: 'token invalid',
        });
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json({
      message: 'Unauthorized',
    });
  }
};

app.delete('/api/users/:userId', verify, (req, res) => {
  const { password, ...others } = users.find((user) => user.id == req.user.id);
  res.status(200).json({
    success: true,
    status: 200,
    data: { ...others },
  });
});

app.post('/api/logout', verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json('you are logout!');
});

app.listen(3000, () => {
  console.log('Backend has Running!');
});
