import bcrypt from 'bcryptjs';
import { query } from '../db.js';
import {createAccesToken} from '../libs/jwt.js';
import {tokenSecret} from '../config.js'
import cookie from "cookie"
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
    const { usuario, correo, contraseña } = req.body;

    try {
        const existingUser = await query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);

        if (existingUser.length > 0) {
        return res.status(400).json({ error: 'El usuario ya existe. Por favor, elige otro nombre de usuario.' });
        }

        const contraseñaHasheada = await bcrypt.hash(contraseña, 10);
        await query('INSERT INTO usuarios (usuario, correo, contraseña) VALUES (?, ?, ?)', [usuario, correo, contraseñaHasheada]);
        
        const token = createAccesToken({ usuario, correo });



        res.cookie('token', token);
        return res.status(201).json({ mensaje: 'Cuenta creada exitosamente.' });
    }catch (error) {
        console.error('Error en el registro:', error);
        return res.status(500).json({ error: 'Error en el registro.' });
    }
};

export const login = async (req, res) => {
    const { usuario, contraseña } = req.body;

    try {
        const [usuarioEncontrado] = await query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);
        console.log("paso")
        if (usuarioEncontrado.length === 0) {
        return res.status(401).json({ error: 'Usuario no encontrado. Por favor, regístrate.' });
        }

        const coincidenciaContraseña = await bcrypt.compare(contraseña, usuarioEncontrado.contraseña);

        if (coincidenciaContraseña) {
            const id = usuarioEncontrado.id_usuario
        const token = createAccesToken({id});

        const serializedToken = cookie.serialize("token",token,{
            httpOnly:true,
            sameSite:"strict",
            maxAge:1000* 60 *60 *24 * 30,
            path:"/",
        })
        res.setHeader("Set-Cookie",serializedToken)
        res.cookie(serializedToken)

        return res.status(200).json({ mensaje: `Inicio de sesión exitoso. ¡Bienvenido, ${usuario}!`,token });
        
        } else {
        return res.status(401).json({ error: 'Contraseña incorrecta. Por favor, inténtalo de nuevo.' });
        }
    } catch (error) {
        console.error('Error en el inicio de sesión:', error);
        return res.status(500).json({ error: 'Error en el inicio de sesión.' });
    }
};

export const logout = (req, res) => {
    res.cookie('token', '', {
        expires: new Date(0),
    });
    return res.sendStatus(200);
};

export const obtener = async (req, res) => {
    const {id} = jwt.verify(req.cookies.token,tokenSecret)
    try {
        const usuarioEncontrado = await query("SELECT * FROM passwords WHERE id_usuario = ?", [id]);       
        res.json(usuarioEncontrado);
    } catch (error) {
        console.error('Error al obtener usuario:', error);
        res.status(500).json({ error: 'Error al obtener usuario.' });
    }
};


export const generarContrasena = async (req, res) => {
    console.log("Hola")
    const { longitud, mayuscula, minuscula, numeros, especiales, sitio } = req.body;
    const {usuario} = req.body; 
    const token = jwt.verify(req.cookies.token,tokenSecret)
    let caracteresSeleccionados = '';
    if (mayuscula && mayuscula !="on") {
        caracteresSeleccionados += 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ';
    }
    if (minuscula && minuscula !="on") {
        caracteresSeleccionados += 'abcdefghijklmnñopqrstuvwxyz';
    }
    if (numeros && numeros !="on") {
        caracteresSeleccionados += '0123456789';
    }
    if (especiales && especiales !="on") {
        caracteresSeleccionados += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    }
    if (!caracteresSeleccionados ) {
        return res.status(400).json({ error: 'Debes seleccionar al menos un tipo de caracteres.' });
    }
    console.log(caracteresSeleccionados);
    const contraseñaGenerada = generarContrasenaAleatoria(longitud, caracteresSeleccionados);
    
    try {
        await guardarContrasenaGenerada(token.id, usuario, contraseñaGenerada, sitio); 
        res.status(200).json({ contraseña: contraseñaGenerada });
    } catch (error) {
        console.error('Error al guardar la contraseña generada:', error);
        res.status(500).json({ error: 'Error al guardar la contraseña generada.' });
    }
};
function generarContrasenaAleatoria(longitud, caracteres) {
    let contraseña = '';
    let long = parseInt(longitud);
    for (let i = 0; i < long; i++) {
      const caracterAleatorio = caracteres.charAt(Math.floor(Math.random() * caracteres.length));
      contraseña += caracterAleatorio;
    }
    return contraseña;
  }

async function guardarContrasenaGenerada(id,usuario, contraseñaGenerada, sitio) {
    try {
        await query('INSERT INTO passwords (id_usuario,usuario, password, sitio) VALUES (?, ?, ?, ?)', [id,usuario, contraseñaGenerada, sitio]);
    } catch (error) {
        throw error;
    }
}  

export const contrasenas = async (req, res) => {
    try {
        const {id} = jwt.verify(req.cookies.token,tokenSecret)
        const contrasenasUsuario = await query('SELECT * FROM passwords WHERE id_usuario = ?', [id]);

        if (contrasenasUsuario.length === 0) {
            return res.status(404).json({ mensaje: 'No se encontraron contraseñas para este usuario.' });
        }
        return res.status(200).json({ contrasenas: contrasenasUsuario });
    } catch (error) {
        console.error('Error al obtener contraseñas del usuario:', error);
        return res.status(500).json({ error: 'Error al obtener contraseñas del usuario.' });
    }
};
