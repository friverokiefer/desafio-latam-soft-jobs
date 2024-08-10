import express from 'express';
import cors from 'cors'; // Importa el paquete cors
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pkg from 'pg';
import dotenv from 'dotenv';

// Cargar las variables de entorno desde el archivo .env
dotenv.config();

const { Pool } = pkg;
const app = express();

// Habilitar CORS para todas las solicitudes
app.use(cors());

app.use(express.json());

// Configuración de la conexión a la base de datos
const pool = new Pool({
    user: 'feliperiverokiefer', // Reemplaza con tu usuario de PostgreSQL
    host: 'localhost',
    database: 'softjobs', // Nombre de la base de datos que creaste
    password: '9807', // Reemplaza con tu contraseña de PostgreSQL
    port: 5432,
});

// Ruta para registrar usuarios
app.post('/usuarios', async (req, res) => {
    try {
        const { email, password, rol, lenguage } = req.body;
        const hashedPassword = bcrypt.hashSync(password, 10); // Encriptar la contraseña
        const result = await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, hashedPassword, rol, lenguage]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Email o contraseña incorrecta' });
        }

        const user = result.rows[0];
        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Email o contraseña incorrecta' });
        }

        // Generar el token JWT usando la clave secreta desde el archivo .env
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Middleware para autenticar usuarios mediante el token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Ruta protegida para obtener información del usuario autenticado
app.get('/usuarios', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.user.email]);
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Iniciar el servidor en el puerto 3000
app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});
