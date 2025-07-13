import express from 'express';
import bcrypt from 'bcrypt';
// import jwt from 'jwtwebtoken';
// import user from "../models/user.js";

import {authenticate} from '../controllers/auth.js'

const router = express.Router();

router.get('/', authenticate);

// router.get('/', (req, res) =>{
//     res.status(200).json({
//         message: "rota autenticação."
//     });
// })

// router.post("/register2", async(req, res) => {
//     const {username, password} = req.body;
//     if (!username || !password) {
//         return res.status(400).json({
//             message: "Nome do usuário e senha são obrigatórios."
//         });
//     }

//     try {
//         const exitingUser = await User.findOne({ username });
//         if (exitingUser) {
//             return res.status(400).json({ message: "Usuário já existe."});
//         }

//         const salt = await bcrypt.genSalt(10);
//         const hashedPassword = await bcrypt.hash(password, salt);

//         const user = new User({ username, password: hashedPassword });
//         await user.save();

//         res.status(201).json({ message: "Usuário registrado com sucesso!", username });
//     } catch (error) {
//         console.error("Erro ao registrar o usuário", error);
//         res.status(500).json({ message: "Erro ao registrar usuário", error: error.message });
//     }
// })

// router.post("/login2", async(req, res) =>{
//     const {username, password} = req.body;
//     if (!username || !password) {
//         return res.status(400).json({
//             message: "Nome do usuário e senha são obrigatórios."
//         });
//     }
//     try{
//         const user = await user.findOne({username})
//         if (!user) {
//             return res.status(404).json({
//                 message: "Usuário não encontrado"
//             });
//         }
//         const isMatch = await bcrypt.compare(password, user.password)
//         if (!isMatch) {
//             return res.status({
//                 message: "Senha incorreta"
//             });
//         } 
//         const token = jwt.sign(
//             {
//             id: user.id,
//             username: user.username
//             },
//             process.env.JWT_SECRET,
//             {
//             expireIn: "1h"
//             }
//         );
//         res.status(200).json({
//             message: "Login bem sucedido!",
//             token,
//             username: user.username
//         });
//     }
//     catch (error){
//         console.error("Erro no login:", error);
//         res.status(500).json({
//             message: "Erro no login",
//             error: error.message
//         });
//     }
// })

export default router;