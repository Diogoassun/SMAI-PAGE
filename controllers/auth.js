
import bcrypt from 'bcrypt';
import jwt from "jsonwebtoken";

import * as dotenv from 'dotenv';
dotenv.config();

const SECRET = process.env.SECRET;

const login = (req, res) => {
    try {

    }
    catch (error) {
        console.error(error);
        res.status(500).json({
            statusCode: 500,
            message: error.message
        });path
    }
}

const authenticate = (req, res) => {
    res.status(200).json({
        message: "rota controller."
    });
}


export {authenticate}