const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
const { default: axios } = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

const consumerKey = 'uVXxQNcB5Y25Enp2MsoaNyAHs';
const consumerSecret = 'M60LUviBcp3FM11Wi1zdH1I2nLhfSU2oLOJ2LF3br2YMkfMKVs';
const callbackUrl = 'http://127.0.0.1:5500/twitterlogin.html';

const oauth = OAuth({
    consumer: { key: consumerKey, secret: consumerSecret },
    signature_method: 'HMAC-SHA1',
    hash_function(base_string, key) {
        return crypto
            .createHmac('sha1', key)
            .update(base_string)
            .digest('base64')
    },
});

app.get('/auth/x/request-token', async (req, res) => {
    const requestData = {
        url: 'https://api.twitter.com/oauth/request_token',
        method: 'POST',
        data: { oauth_callback: callbackUrl },
    };

    try {
        const response = await fetch(requestData.url, {
            method: requestData.method,
            headers: oauth.toHeader(oauth.authorize(requestData)),
        });

        const data = await response.text();
        const requestToken = new URLSearchParams(data).get('oauth_token');
        const authUrl = `https://api.twitter.com/oauth/authenticate?oauth_token=${requestToken}`;

        res.json({ authUrl });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to get request token' });
    }
});

app.post('/auth/x/access-token', async (req, res) => {
    const { oauthToken, oauthVerifier } = req.body;

    const requestData = {
        url: 'https://api.twitter.com/oauth/access_token',
        method: 'POST',
        data: { oauth_token: oauthToken, oauth_verifier: oauthVerifier },
    };

    try {
        const response = await fetch(requestData.url, {
            method: requestData.method,
            headers: oauth.toHeader(oauth.authorize(requestData)),
        });

        const data = await response.text();
        const accessToken = new URLSearchParams(data).get('oauth_token');
        const accessTokenSecret = new URLSearchParams(data).get('oauth_token_secret');

        res.json({ accessToken, accessTokenSecret });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to get access token' });
    }
});

const LINKEDIN_CLIENT_ID = "77pt32wd1p75jg";
const LINKEDIN_CLIENT_SECRET = "37I6EelllTjE0Yo0";
const REDIRECT_URI = "http://127.0.0.1:5500/linkedinsignin.html";

app.get("/auth/linkedin", (req, res) => {
  const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${LINKEDIN_CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=profile%20email%20openid%20w_member_social`;
  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  const { code } = req.query;
  try {
    const myHeaders = new Headers();
    myHeaders.append("Content-Type", "application/x-www-form-urlencoded");
    myHeaders.append(
      "Cookie",
      'bcookie="v=2&7cdf582a-b908-4e46-837c-81da189ab821"; lang=v=2&lang=en-us; lidc="b=VB42:s=V:r=V:a=V:p=V:g=5331:u=1416:x=1:i=1726810535:t=1726872792:v=2:sig=AQGU2Xs_jnrTCfNZ_ZgFG2FbBpy73ibZ"; bscookie="v=1&202409180814598c36ea42-3f88-4d48-89e4-ce7795d33353AQGpwvpqRauUCxTVMqkijJ9iVAgrmFCP"'
    );

    const urlencoded = new URLSearchParams();
    urlencoded.append("grant_type", "authorization_code");
    urlencoded.append("code", code);
    urlencoded.append(
      "redirect_uri",
      REDIRECT_URI
    );
    urlencoded.append("client_id", LINKEDIN_CLIENT_ID);
    urlencoded.append("client_secret", LINKEDIN_CLIENT_SECRET);

    const requestOptions = {
      method: "POST",
      headers: myHeaders,
      body: urlencoded,
      redirect: "follow",
    };
    let responsevalue = {};
    fetch("https://www.linkedin.com/oauth/v2/accessToken", requestOptions)
      .then((response) => response.text())
      .then(async (result) => {

        const tokenData = await JSON.parse(result);
        console.log(tokenData.access_token)
        const userProfile = await getUserProfile(tokenData.access_token);
        res.json({...userProfile});
      })
      .catch((error) => console.error(error));
  } catch (error) {
    console.error(
      "Error:",
      error.response ? error.response.data : error.message
    );
    res.status(500).json({ error: "An error occurred during authentication" });
  }
});

async function getUserProfile(accessToken) {
  const { data } = await axios.get("https://api.linkedin.com/v2/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return {
    id: data.id,
    name: data.name,
    email : data.email,
  };
}

async function getUserEmail(accessToken) {
  const { data } = await axios.get(
    "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );
  return { email: data.elements[0]["handle~"].emailAddress };
 }


const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

