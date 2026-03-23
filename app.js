// app.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const connection = require('./db');

const app = express();
const port = 3000;

app.use(cors({
    origin: ['http://localhost:3000'],
    credentials: true
}));

app.use(helmet({
    frameguard: {
        action: 'deny'
    },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "http://localhost:3000"],
            connectSrc: ["'self'", "http://localhost:3000"],
            frameAncestors: ["'self'"]
        }
    }
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

const csrfProtection = csurf({ cookie: true });
app.use((req, res, next) => {

    // Saltarse CSRF para APIs
    if (req.path.startsWith('/api')) {
        return next();
    }

    //Aplicar CSRF al resto (formularios normales)
    csrfProtection(req, res, next);

});

app.get('/csrf-token', (req, res) => {
    console.log('Petición recibida a /csrf-token');
    res.json({ csrfToken: req.csrfToken() });
});

const loginAttempts = {};

app.post('/register', async (req, res) => {
    try {
        const { nombre, correo, NO_Documento, contraseña } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(contraseña, salt);

        const query = "INSERT INTO usuarios (nombre, NO_Documento, correo, contrasenia, rol) VALUES (?, ?, ?, ?, 'Usuario')";

        connection.query(query, [nombre, NO_Documento, correo, hashedPassword], (err) => {
            if (err) {
                console.error('Error al registrar el usuario:', err);
                return res.status(500).json({ message_registro: 'Error al registrar el usuario' });
            }
            res.json({ message_registro: 'Se ha registrado correctamente' });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message_registro: 'Error en el servidor' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { correo, NO_Documento, contraseña } = req.body;

        console.log("BODY COMPLETO:", req.body);
        console.log("Correo recibido:", correo);
        console.log("Documento recibido:", NO_Documento);
        console.log("Contraseña recibida:", contraseña);

        const identificador = correo || NO_Documento;

        if (!loginAttempts[identificador]) {
            loginAttempts[identificador] = { count: 0, lastAttempt: Date.now() };
        }

        const currentTime = Date.now();
        const timeSinceLastAttempt = currentTime - loginAttempts[identificador].lastAttempt;

        if (timeSinceLastAttempt < 300000 && loginAttempts[identificador].count >= 5) {
            return res.status(429).json({ message_ingreso: 'Demasiados intentos, intenta más tarde' });
        }

        let campo = correo ? 'correo' : 'NO_Documento';
        console.log("Campo usado en SQL:", campo);
        console.log("Identificador:", identificador);

        const query = `SELECT * FROM usuarios WHERE ${campo} = ?`;

        connection.query(query, [identificador], async (err, results) => {
            if (err) {
                console.error('Error SQL:', err);
                return res.status(500).json({ message_ingreso: 'Error en el servidor' });
            }

            console.log("Resultados SQL:", results);

            if (results.length > 0) {
                const user = results[0];

                console.log("Hash guardado en DB:", user.contrasenia);

                const validPassword = await bcrypt.compare(contraseña, user.contrasenia);

                console.log("Resultado bcrypt:", validPassword);

                if (validPassword) {
                    loginAttempts[identificador] = { count: 0, lastAttempt: 0 };

                    res.json({
                        message_ingreso: 'Correcto',
                        usuario: {
                            id: user.id_usuario,
                            nombre: user.nombre,
                            correo: user.correo,
                            NO_Documento: user.NO_Documento
                        }
                    });
                } else {
                    loginAttempts[identificador].count++;
                    loginAttempts[identificador].lastAttempt = currentTime;
                    res.json({ message_ingreso: 'Correo o Contraseña inválido' });
                }

            } else {
                console.log("Usuario NO encontrado");

                loginAttempts[identificador].count++;
                loginAttempts[identificador].lastAttempt = currentTime;
                res.json({ message_ingreso: 'Correo o Contraseña inválido' });
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message_ingreso: 'Error en el servidor' });
    }
});

//  Obtener habitaciones
app.get('/api/habitaciones', (req, res) => {
    connection.query('SELECT * FROM habitaciones', (err, results) => {
        if(err) return res.status(500).json({error:'Error DB'});
        res.json(results);
    });
});

//  Crear reserva
app.post('/api/reservar', (req, res) => {

    const { id_usuario, id_habitacion, fecha_entrada, fecha_salida } = req.body;

    const query = `
    INSERT INTO reservas (id_usuario, id_habitacion, fecha_entrada, fecha_salida)
    VALUES (?, ?, ?, ?)`;

    connection.query(query, [id_usuario, id_habitacion, fecha_entrada, fecha_salida], (err) => {
        if(err) return res.status(500).json({message:'Error al reservar'});
        res.json({message:'Reserva creada correctamente'});
    });

});
//funcion para borrar 
app.delete('/api/eliminar-reserva/:id', (req, res) => {

    const id_reserva = req.params.id;

    connection.query(
        "DELETE FROM reservas WHERE id_reserva = ?",
        [id_reserva],
        (err) => {
            if(err) return res.status(500).json({message:'Error'});
            res.json({message:'Reserva eliminada'});
        }
    );
});


app.listen(port, () => {
    console.log(`Ingresa a este link en tu página web http://localhost:${port}`);
});

// app.js
app.get('/api/reservas', (req, res) => {
    const id_usuario = req.query.id_usuario;
    if(!id_usuario) return res.status(400).json({error:'Falta id_usuario'});

    const query = `
    SELECT r.id_reserva, h.numero, h.tipo, r.fecha_entrada, r.fecha_salida
    FROM reservas r
    JOIN habitaciones h ON r.id_habitacion = h.id_habitacion
    WHERE r.id_usuario = ?`;

    connection.query(query, [id_usuario], (err, results) => {
        if(err) return res.status(500).json({error:'Error DB', details: err});
        res.json(results);
    });
});