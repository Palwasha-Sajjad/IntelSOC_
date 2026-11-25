import {useEffect,useState} from 'react';
import type {FormEvent} from 'react';
import {NavLink,Navigate,Routes,Route,useLocation,useNavigate} from 'react-router-dom';
import {useQuery,useQueryClient} from '@tanstack/react-query';
import {Shield,LayoutDashboard,List,Bell,Fingerprint,Brain,Monitor,Users,Settings,Server,Sun,Moon,LogOut} from 'lucide-react';
import {api,post,ApiError} from './api/client';
import type {User} from './types';
import {AuthForm} from './AuthForm';
import type {Mode} from './AuthForm';
import {Overview} from './Overview';

const sessionKey=['session'];
const err=(e:unknown)=>e instanceof Error?e.message:'Request failed';
const unauthorized=(e:unknown)=>e instanceof ApiError&&e.status===401;
const nav=[
  {path:'/',name:'Overview',icon:LayoutDashboard,level:0},
  {path:'/events',name:'Events',icon:List,level:0},
  {path:'/alerts',name:'Alerts',icon:Bell,level:0},
  {path:'/incidents',name:'Incidents',icon:Fingerprint,level:1},
  {path:'/ai',name:'AI Analysis',icon:Brain,level:1},
  {path:'/devices',name:'Devices',icon:Monitor,level:2},
  {path:'/users',name:'User Management',icon:Users,level:2},
  {path:'/health',name:'System Health',icon:Server,level:2},
  {path:'/settings',name:'Settings',icon:Settings,level:0}
];

function SettingsPage({user,onEnd}:{user:User;onEnd:()=>void}){
  const [current,setCurrent]=useState(''),[next,setNext]=useState(''),[confirm,setConfirm]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function submit(e:FormEvent){e.preventDefault();if(busy)return;setError('');if(next!==confirm){setError('Passwords do not match.');return;}setBusy(true);try{await post('/auth/change-password',{current_password:current,new_password:next});onEnd();}catch(e){setError(err(e));}finally{setBusy(false);setCurrent('');setNext('');setConfirm('');}}
  return <><h1>Settings</h1><section className="panel"><h2>Profile</h2><p>{user.username} · {user.role}</p><p>{user.email}</p></section><section className="panel narrow"><h2>Change password</h2><p className="muted">Changing your password ends all existing sessions.</p>{error&&<p role="alert" className="error">{error}</p>}<form onSubmit={submit}><label>Current password<input type="password" autoComplete="current-password" required maxLength={128} value={current} onChange={e=>setCurrent(e.target.value)}/></label><label>New password<input type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={next} onChange={e=>setNext(e.target.value)}/></label><label>Confirm password<input type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={confirm} onChange={e=>setConfirm(e.target.value)}/></label><button className="primary" disabled={busy}>{busy?'Please wait…':'Change password'}</button></form></section></>;
}

function Dashboard({user,onEnd,theme,toggle}:{user:User;onEnd:()=>void;theme:string;toggle:()=>void}){
  const [error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [clock,setClock]=useState(new Date());
  useEffect(()=>{const id=setInterval(()=>setClock(new Date()),1000);return ()=>clearInterval(id);},[]);
  async function logout(){if(busy)return;setBusy(true);setError('');try{await post('/auth/logout',{});onEnd();}catch(e){setError(err(e));}finally{setBusy(false);}}
  const available=nav.filter(n=>n.level<=(user.role==='administrator'?2:user.role==='analyst'?1:0));
  return <div className="shell"><aside><div className="brand"><Shield size={25}/> IntelSOC</div><p className="nav-label">SECURITY OPERATIONS</p><nav>{available.map(n=><NavLink end={n.path==='/'} key={n.path} to={n.path}><n.icon size={18}/><span>{n.name}</span>{!['/','/settings'].includes(n.path)&&<small className="planned">Soon</small>}</NavLink>)}</nav><p className="sidebar-foot">Private SOC workspace</p></aside><div className="workspace"><header><span className="muted">Security workspace</span><div className="header-actions"><time className="clock">{clock.toLocaleString()}</time><button aria-label="Toggle theme" onClick={toggle}>{theme==='dark'?<Sun size={18}/>:<Moon size={18}/>}</button><span className="identity"><strong>{user.username}</strong><small>{user.role}</small></span><button onClick={()=>void logout()} disabled={busy}><LogOut size={16}/> Sign out</button></div></header><main className="page">{error&&<p role="alert" className="error">{error}</p>}<Routes><Route path="/" element={<Overview user={user}/>}/><Route path="/settings" element={<SettingsPage user={user} onEnd={onEnd}/>}/>{available.filter(n=>!['/','/settings'].includes(n.path)).map(n=><Route key={n.path} path={n.path} element={<section className="panel"><h1>{n.name}</h1><p className="muted">Not integrated yet.</p></section>}/>)}<Route path="*" element={<Navigate to="/" replace/>}/></Routes></main></div></div>;
}

const publicPaths:Record<string,Mode>={'/login':'login','/forgot-password':'forgot','/activate':'activate','/reset-password':'reset'};
export function App(){
  const qc=useQueryClient(),navigate=useNavigate(),location=useLocation();
  const publicMode:Mode|undefined=publicPaths[location.pathname];
  const [theme,setTheme]=useState(()=>localStorage.getItem('intelsoc-theme')==='light'?'light':'dark');
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem('intelsoc-theme',theme);},[theme]);
  const session=useQuery({queryKey:sessionKey,queryFn:({signal})=>api<User>('/auth/me',{signal}),enabled:!publicMode,refetchInterval:30000,staleTime:0});
  useEffect(()=>{if(!publicMode&&session.isError&&unauthorized(session.error)){qc.removeQueries({predicate:q=>q.queryKey[0]!=='session'});navigate('/login',{replace:true});}},[publicMode,session.isError,session.error,qc,navigate]);
  useEffect(()=>{if(session.data){qc.removeQueries({predicate:q=>['summary','alerts'].includes(String(q.queryKey[0]))&&(q.queryKey[1]!==session.data?.user_id||q.queryKey[2]!==session.data?.role)});}},[session.data,qc]);
  async function onLogin(){await qc.cancelQueries();qc.clear();await qc.fetchQuery({queryKey:sessionKey,queryFn:({signal})=>api<User>('/auth/me',{signal})});}
  function onEnd(){void qc.cancelQueries();qc.clear();navigate('/login',{replace:true});}
  if(publicMode)return <AuthForm key={publicMode} mode={publicMode} onLogin={onLogin}/>;
  if(session.isError)return unauthorized(session.error)?<Navigate to="/login" replace/>:<main className="auth-screen"><section className="auth-card"><h1>Connection unavailable</h1><p role="alert">{err(session.error)}</p><button onClick={()=>void session.refetch()}>Retry</button></section></main>;
  if(!session.data)return <main className="auth-screen">Checking secure session…</main>;
  return <Dashboard key={session.data.user_id+session.data.role} user={session.data} onEnd={onEnd} theme={theme} toggle={()=>setTheme(t=>t==='dark'?'light':'dark')}/>;
}
