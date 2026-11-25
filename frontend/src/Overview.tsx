import { useQuery } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import { api } from './api/client';
import type { User, DashboardSummary, AlertSummary } from './types';
const fmt=(n:number)=>n.toLocaleString();
const date=(s:string)=>new Date(s).toLocaleString();
export function Overview({user}:{user:User}){
  const summary=useQuery({queryKey:['summary',user.user_id,user.role],queryFn:({signal})=>api<DashboardSummary>('/dashboard/summary',{signal}),refetchInterval:30000});
  const alerts=useQuery({queryKey:['alerts',user.user_id,user.role],queryFn:({signal})=>api<AlertSummary[]>('/alerts?limit=8',{signal}),refetchInterval:30000});
  const s=summary.data;
  const risk=s?[['Normal',s.normal_risk],['Suspicious',s.suspicious_risk],['Malicious',s.malicious_risk],['Unassessed',s.unassessed_alerts]] as const:[];
  const total=risk.reduce((sum,r)=>sum+r[1],0);
  return <><div className="page-heading"><div><h1>Security overview</h1><p className="muted">Monitor registered endpoints and detected threats.</p></div><button disabled={summary.isFetching||alerts.isFetching} onClick={()=>{void summary.refetch();void alerts.refetch();}}><RefreshCw size={16}/> Refresh</button></div>
  {summary.isError?<p role="alert" className="error">{summary.error.message}</p>:summary.isPending?<p>Loading security statistics…</p>:s&&<>
  <p className="muted small">Last generated: {date(s.generated_at)} · Refreshes every 30 seconds</p>
  <div className="metrics">{[['Total events',s.total_events,'Last 24h: '+fmt(s.events_last_24h)],['Open alerts',s.open_alerts,'Total: '+fmt(s.total_alerts)],['Open incidents',s.open_incidents,'Total: '+fmt(s.total_incidents)],['Active registrations',s.active_registrations,'Registered: '+fmt(s.registered_devices)]].map(([label,value,note])=><section className="panel metric" key={label}><span>{label}</span><strong>{fmt(Number(value))}</strong><small>{note}</small></section>)}</div>
  <section className="panel"><h2>Alert risk distribution</h2>{total===0?<p className="muted">No alert risk data available.</p>:<div className="risk-bars">{risk.map(([label,n])=><div className="risk-row" key={label}><span>{label}</span><progress className={label.toLowerCase()} value={n} max={total}/><strong>{fmt(n)}</strong></div>)}</div>}</section></>}
  <section className="panel"><h2>Recent alerts</h2>{alerts.isError?<p role="alert" className="error">{alerts.error.message}</p>:alerts.isPending?<p>Loading alerts…</p>:!alerts.data?.length?<p className="muted">No alerts found.</p>:<div className="table-wrap"><table><thead><tr>{['Alert','Endpoint','Severity','Risk','Status','Created'].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{alerts.data.map(a=><tr key={a.alert_id}><td>{a.title}</td><td>{a.hostname??'—'}</td><td>{a.severity}</td><td>{a.overall_score??'Unassessed'}</td><td>{a.status}</td><td>{date(a.created_at)}</td></tr>)}</tbody></table></div>}</section></>;
}
