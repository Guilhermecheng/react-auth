import axios, { AxiosError } from 'axios';
import { parseCookies, setCookie } from 'nookies';
import { signOut } from '../contexts/AuthContext';
import { AuthTokenError } from './errors/AuthTokenError';

let isRefreshing = false;
let failedRequestQeue = [];

export function setupApiClient(context = undefined) {
    let cookies = parseCookies(context);

    const api = axios.create({
        baseURL: 'http://localhost:3333',
        headers: {
            Authorization: `Bearer ${cookies['nextauth.token']}`
        }
    });
    
    api.interceptors.response.use(response => {
        return response;
    }, (error: AxiosError) => {
        if(error.response.status === 401) {
            if(error.response.data?.code === 'token.expired') {
                // renovar o item
                cookies = parseCookies(context);
    
                const { 'nextauth.refreshToken': refreshToken } = cookies;
                const originalConfig = error.config;
    
                if(!isRefreshing) {
                    isRefreshing = true;
                    console.log('refresh')
    
                    api.post('/refresh', {
                        refreshToken,
                    }).then(response => {
                        const { token } = response.data;
        
                        setCookie(context, 'nextauth.token', token, {
                            maxAge: 60 * 60 * 24 * 30, // 30 days
                            path: '/',
                        })
                        setCookie(context, 'nextauth.refreshToken', response.data.refreshToken, {
                            maxAge: 60 * 60 * 24 * 30, // 30 days
                            path: '/',
                        })
        
                        api.defaults.headers['Authorization'] = `Bearer ${token}`;
    
                        failedRequestQeue.forEach(request => request.onSuccess(token))
                        failedRequestQeue = [];
                    }).catch(err => {
                        failedRequestQeue.forEach(request => request.onFailure(err))
                        failedRequestQeue = [];
    
                        // for client side logout
                        if(typeof window !== 'undefined') {
                            signOut()
                        }
    
                    }).finally(() => {
                        isRefreshing = false;
                    })
                }
    
                return new Promise((resolve, reject) => {
                    failedRequestQeue.push({
                        onSuccess: (token: string) => {
                            originalConfig.headers['Authorization'] = `Bearer ${token}`;
    
                            resolve(api(originalConfig));
                        },
                        onFailure: (err: AxiosError) => {
                            reject(err);
                        },
                    })
                })
            } else {
                // deslogar o user
                if(typeof window !== 'undefined') {
                    signOut()
                } else {
                    return Promise.reject(new AuthTokenError());
                }
            }
        }
    
        return Promise.reject(error);
    })

    return api;
}