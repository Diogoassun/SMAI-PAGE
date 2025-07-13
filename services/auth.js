import express from 'express'
import jwt from 'jsonwebtoken'
import * as dotenv from 'dotenv'

dotenv.config();

const app = express();

const users = [
    {id: 1, username: 'leo', password: '123456', role: 'admin'},
    {id: 2, username: 'oel', password: '654321', role: 'user'}
]

app.get('/log-in', (req, res) => {
    const {username, password} = req.body;

    const user =  users.find(user => user.user == username && user.password == password);

    if (user){

        const userPayload =  {
            id: user.id,
            username: user.username,
            role: user.role
        };

        const acessToken= jwt.sign(
            userPayload,
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '60s' }
        );

        const refreshToken= jwt.sign(
            userPayload,
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1h' }
        );


        res.status(201).json({ message: acessToken, refreshToken});
    }
    else {
        res.status(401).json({ message: "usuario não é válido" });
    }
})