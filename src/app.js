import express  from "express";
import morgan from "morgan"
import cookieParser from "cookie-parser";
import authRoutes from './routes/auth.routes.js'
import cors from 'cors'

const app = express();

app.use(cors({credentials:true, origin:true}));
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());
app.use(authRoutes);

export default app;