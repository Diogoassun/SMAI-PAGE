import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

app.use(express.static(path.join(__dirname, 'public')))

app.get('/status', (request, response) => {
    console.log('✅ Rota /status foi chamada!');
    response.json({
        status: "OK",
        message: "Servidor está funcionando perfeitamente!",
        timestamp: new Date().toISOString()
    });
});

app.get('/', (resquest, response) => {
    return response.send('<h1>hello</h1>')
})

app.get('/about', (resquest, response) => {
    return response.send('<h1>about</h1>')
})


app.use((request, response, next) => {
    response.status(404).sendFile(path.join(__dirname, 'public', '/not-found.html'))
})

app.listen(3333)