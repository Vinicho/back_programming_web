import jwt from 'jsonwebtoken';
import {tokenSecret} from "../config.js";

export function createAccesToken(payload){
  
        const token = jwt.sign(
            payload
            ,
            tokenSecret,
            {
                expiresIn: "1d"
            }
        );
        return token;
    
}