import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { post } from './api/client';

export type Mode = 'login' | 'forgot' | 'activate' | 'reset';
const initialPath = window.location.pathname;
let emailToken = ['/activate','/reset-password'].includes(initialPath)
  ? new URLSearchParams(window.location.hash.slice(1)).get('token') || '' : '';
if (['/activate','/reset-password'].includes(initialPath) && window.location.hash)
  history.replaceState(null, '', initialPath);

export function AuthForm({mode,onLogin}:{mode:Mode;onLogin:()=>Promise<void>}) {
  const [email,setEmail]=useState(''),[password,setPassword]=useState(''),[confirm,setConfirm]=useState('');
  const [token,setToken]=useState(()=>(mode==='activate'&&initialPath==='/activate')||(mode==='reset'&&initialPath==='/reset-password')?emailToken:'');
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
  const navigate=useNavigate();
  const link=mode==='activate'||mode==='reset';
  async function submit(e:FormEvent){
    e.preventDefault(); if(busy)return; setError('');
    if(link&&password!==confirm){setError('Passwords do not match.');return;}
    if(link&&!/^[A-Za-z0-9_-]{43}$/.test(token)){setError('Open the valid link from your email.');return;}
    setBusy(true);
    try{
      if(mode==='login'){await post('/auth/login',{email,password});await onLogin();navigate('/',{replace:true});}
      else{
        const result=await post<{message:string}>(mode==='forgot'?'/auth/forgot-password':mode==='activate'?'/auth/activate':'/auth/reset-password',mode==='forgot'?{email}:mode==='activate'?{invitation_token:token,password}:{reset_token:token,password});
        setNotice(result.message);setToken('');emailToken='';
      }
    }catch(e){setError(e instanceof Error?e.message:'Request failed');}
    finally{setBusy(false);setPassword('');setConfirm('');}
  }
  return <main className="auth-screen"><section className="auth-card"><div className="brand"><Shield size={28}/> IntelSOC</div><p className="muted">Smart Threat Intelligence and Response System</p><h1>{{login:'Sign in',forgot:'Recover password',activate:'Activate account',reset:'Reset password'}[mode]}</h1>
  {error&&<p role="alert" className="error">{error}</p>}
  {notice?<p role="status" className="notice">{notice}</p>:<form onSubmit={submit}>
  {!link&&<label>Email<input required type="email" autoComplete="username" maxLength={254} value={email} onChange={e=>setEmail(e.target.value)}/></label>}
  {link&&!token&&<p className="error">Open your original email link.</p>}
  {mode!=='forgot'&&<label>Password<input required type="password" autoComplete={link?'new-password':'current-password'} minLength={link?15:1} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)}/></label>}
  {link&&<label>Confirm password<input required type="password" autoComplete="new-password" minLength={15} maxLength={128} value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>}
  <button className="primary" disabled={busy||(link&&!token)}>{busy?'Please wait…':mode==='login'?'Sign in':mode==='forgot'?'Request reset email':'Set password'}</button></form>}
  <Link to={mode==='login'?'/forgot-password':'/login'}>{mode==='login'?'Forgot password?':'Back to sign in'}</Link></section></main>;
}
