const express = require('express');
const cors = require('cors')
const jwt = require('jsonwebtoken');
const app = express();
app.use(cors());
app.use(express.json());




//database
const database = [
    {
        id: '1',
        username: 'admin',
        password: '12345',
        role: 'admin'
    },
    {
        id: '2',
        username: 'user',
        password: '12345',
        role: 'user'
    }
];



const verification = (req, res, next) => {
    const token = req.headers.authorization;
    console.log({ token });
    // console.log(token, req.body.token);
    if (token) {
        const spliceToken = token.replace('Bearer ', '');
        console.log({ spliceToken });
        jwt.verify(spliceToken, 'secret', (err, data) => {
            if (err) {
                console.log(err);
                res.status(502).send('invalid token');
            } else {
                req.user = data;
                next();
            }
        })
    } else {

        res.status(502).send('Authorization failed Access Token');

    }

}



const createAccessToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username, role: user.role }, 'secret', { expiresIn: '15m' });
}

const createRefreshToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username, role: user.role }, 'RefreshTokenSecret');
}




var tokenStore = [];

//refresh token
app.post('/auth/refresh', (req, res) => {
    const token = req.body.token;

    if (!token) return res.status(502).json('Authorization failed');
    if (!tokenStore.includes(token)) return res.status(502).json('invalid token');

    jwt.verify(token, 'RefreshTokenSecret', (err, data) => {

        if (err) return res.status(502).json('invalid token');

        tokenStore = tokenStore.filter(token => token !== token);
        const accessToken = createAccessToken(data);
        const refreshToken = createRefreshToken(data);
        tokenStore.push(refreshToken);
        res.json({
            accessToken,
            refreshToken,
        })
    })
});

//create access token
app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;

    const user = database.find(u => u.username === username && u.password === password);

    if (user) {
        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        tokenStore.push(refreshToken);

        res.json({
            id: user.id,
            username: user.username,
            role: user.role,
            accessToken,
            refreshToken
        });

    } else {
        res.status(401).json('Your are unauthorize');
    }
});

app.delete('/delete/:id', verification, (req, res) => {
    // console.log(req.user.id, req.params.id);
    if (req.user.id === req.params.id || req.user.role === 'admin') {
        res.json(`${req.params.id} no id user has been deleted successfully`);
    } else {
        res.status(401).json('you are not permitee to delete the user');
    }
});

app.post('/logout', (req, res) => {
    const token = req.body.token;
    if (!token) return res.status(502).json('invalid token');
    tokenStore = tokenStore.filter(t => token !== t);
    res.send('logout successfully');
});

app.listen(9050, () => {
    console.log('Server is running', 9050);

});