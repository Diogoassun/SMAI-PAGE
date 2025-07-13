import express from "express";
import router from "../routes/authRoutes";

const app = express();

app.use('',(resquest, response, next) =>{

});

const pathRoutes = [
    {path: '/sing-in', whenAuthenticated: 'redirect'},
    {path: '/register', whenAuthenticated: 'redirect'},
    {path: '/dashboard', whenAuthenticated: 'next'}
]

const REDIRECT_WHEN_NOT_AUTHENTICATED_ROUTE = 'sign-in';

export function middleware(NextRequest){
    const path = resquset.nextUrl.pathName;
    const publicRoute = publicRoutes.find(route => route.path === path)

    return NextRequest.next();
}

export {middleware};