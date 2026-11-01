require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const path = require("path");
const pool = require("./db");

//importamos la estrategia local
const LocalStrategy = require("passport-local").Strategy;

const app = express();
const PORT = process.env.PORT || 3000;

//configuracion de ejs
app.set ("views", path.join(__dirname, "views"));
app.set ("view engine", "ejs");

//Middlewares
app.use(express.urlencoded({extended: false}));
app.use(express.static(path.join(__dirname, "public")));

function isAuth(req, res, next){
    if (req.isAuthenticated()){
        //si esta logueado, pasa
        next();
    }
    else{
        //sino esta logueado lo mandamos al login
        res.redirect("/login");
    }
}
function isAdmin(req, res, next){
    if (req.isAuthenticated() && req.user.is_admin === true){
        next();
    }
    else{
        res.redirect("/");
    }
}

//Sesiones de Odin (usa "cats", nosotros usamos nuestro .env)
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,    
    })
);

//inicializamos passport
app.use(passport.initialize());
app.use(passport.session());

//Configuramos la estrategia local (Esto pide odin ahora)
passport.use(
    new LocalStrategy(async (username, password, done) =>{
        try{
            const {rows} = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
            const user = rows[0];
            if (!user){
                return done (null, false, { message: "Usuario no encontrado"});
            }
            const match = await bcrypt.compare(password, user.password);

            if (!match){
                return done(null, false, {message: "Contraseña incorrecta"});
            }
            return done(null, user);
        }
        catch (err){
            return done(err);
        }
    })
);

//Funciones de serializacion (Clave para que la sesion se mantenga)
passport.serializeUser((user, done)=>{
    done(null, user.id);
});

passport.deserializeUser(async (id, done)=>{
    try{
        const {rows} = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
        done(null, rows[0]);
    }
    catch(err){
        done(err);
    }
});

//Ruta base
app.get("/", async (req, res, next)=>{
    try{
        const {rows} = await pool.query(`SELECT messages.*, users.full_name FROM messages
        JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC`);
        res.render("index", {user: req.user, messages: rows});
    }
    catch(err){
        next(err);
    }
});
app.get("/secreto", isAuth, (req, res)=>{
    res.send(`¡Felicidades ${req.user.username}! estas viendo una pagina ultra secreta solo por estar logueado`);
});
app.get("/join-club", isAuth,(req, res)=>{
    res.render("join-club");
})
app.get("/new-message", isAuth, (req, res)=>{
    res.render("new-message");
});
app.post("/new-message", isAuth, async(req, res, next)=>{
    try{
        await pool.query("INSERT INTO messages (title, text, user_id) VALUES ($1, $2, $3)", [
            req.body.title,
            req.body.text,
            req.user.id,
        ]);
        res.redirect("/");
    }
    catch(err){
        return next(err);
    }
});
app.post("/delete/:id", isAdmin, async (req, res, next)=>{
     try{
        await pool.query("DELETE FROM messages WHERE id = $1", [req.params.id]);
        res.redirect("/")
     }
     catch(err){
        return next(err)
     }
});
app.get("/login", (req,res)=> res.render("login"));
app.get("/sign-up", (req, res)=> res.render("sign-up"));

app.post("/sign-up", async (req, res, next)=>{
    try{
        const {username, password, confirm_password, full_name} = req.body
        if (password !== confirm_password){
            return res.redirect("/sign-up");
        }
        if (password.length < 8){
            return res.render("sign-up", {error: "La contraseña debe tener al menos 8 caracteres"});
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        await pool.query("INSERT INTO users (username, password, full_name) VALUES ($1, $2, $3)", [
            username,
            hashedPassword,
            full_name,
        ]);
        res.redirect("/login");
    }
    catch (err){
        return next(err);
    }
});
app.post("/join-club", isAuth, async (req, res, next)=>{
    try{
        const secretCode = req.body.secret_code;
        const SECRET_CLUB_PASSWORD = "gatitos123";

        if (secretCode === SECRET_CLUB_PASSWORD){
            await pool.query("UPDATE users SET is_member = true WHERE id = $1", [req.user.id]);
            res.send(`¡Felicitaciones ${req.user.username}! Ahora eres miembro.`)
        }
        else{
            res.send("Contraseña incorrecta, intenta de nuevo.");
        }
    }
    catch(err){
        return next(err);
    }
});
app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect:"/",
    failureMessage: true,
    })
);
app.post("/logout", (req, res, next)=>{
    req.logout((err)=>{
        if (err){return next(err);}
        res.redirect("/");
    });
});
app.listen(PORT, ()=>{
    console.log(`Servidor en http://localhost: ${PORT}`);
});

