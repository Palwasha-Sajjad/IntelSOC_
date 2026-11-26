import {useState} from 'react';
import type {FormEvent} from 'react';
import {useQuery} from '@tanstack/react-query';
import {api} from './api/client';
import type {User} from './types';

export type Row = Record<string, unknown>;
export type PageKind = 'events'|'alerts'|'incidents'|'devices';
const configs = {
  events: {title:'Security events', id:'event_id', columns:['event_time','hostname','source','event_type','src_ip'], filters:['hostname','event_type','device_id']},
  alerts: {title:'Security alerts', id:'alert_id', columns:['created_at','title','hostname','source_ip','severity','status','overall_score','classification'], filters:['severity','status','device_id']},
  incidents: {title:'Incidents', id:'incident_id', columns:['last_seen_at','title','hostname','source_ip','severity','status','alert_count'], filters:['severity','status','device_id']},
  devices: {title:'Registered endpoints', id:'device_id', columns:['hostname','platform','status','criticality','last_seen_at','device_id'], filters:['hostname','platform','status','criticality']},
};
export const label=(s:string)=>s.replace(/_/g,' ').replace(/^./,c=>c.toUpperCase());
export function value(v:unknown,k=''):string {
  if(v===null||v===undefined)return '—';
  if(typeof v==='object')return JSON.stringify(v,null,2);
  if(typeof v==='string'&&(/(_at|_time)$/.test(k))&&!Number.isNaN(Date.parse(v)))return new Date(v).toLocaleString();
  return String(v);
}
export function Fields({row}:{row:Row}){
  return <dl className="fields">{Object.entries(row).map(([k,v])=><div key={k}><dt>{label(k)}</dt><dd>{typeof v==='object'&&v!==null?<pre>{value(v,k)}</pre>:value(v,k)}</dd></div>)}</dl>;
}
export function Records({rows,columns,id,onSelect}:{rows:Row[];columns:string[];id:string;onSelect?:(row:Row)=>void}){
  if(!rows.length)return <p className="muted">No matching records.</p>;
  return <div className="table-wrap"><table><thead><tr>{columns.map(c=><th key={c}>{label(c)}</th>)}{onSelect&&<th>Details</th>}</tr></thead><tbody>{rows.map((row,i)=><tr key={String(row[id]??i)}>{columns.map(c=><td key={c}>{value(row[c],c)}</td>)}{onSelect&&<td><button onClick={()=>onSelect(row)}>Inspect</button></td>}</tr>)}</tbody></table></div>;
}
function RemoteSection({user,path,title}:{user:User;path:string;title:string}){
  const q=useQuery({queryKey:['monitor',user.user_id,user.role,path],queryFn:({signal})=>api<unknown>(path,{signal})});
  return <section className="panel"><h2>{title}</h2>{q.isError?<p className="error" role="alert">{q.error.message}</p>:q.isPending?<p>Loading…</p>:Array.isArray(q.data)?q.data.length?q.data.map((r,i)=><section className="record" key={i}><Fields row={r as Row}/></section>):<p className="muted">No linked records available.</p>:q.data&&typeof q.data==='object'?<Fields row={q.data as Row}/>:<p className="muted">No data available.</p>}</section>;
}
export function MonitorPage({user,kind}:{user:User;kind:PageKind}){
  const cfg=configs[kind],size=50;
  const [draft,setDraft]=useState<Record<string,string>>({}),[filters,setFilters]=useState<Record<string,string>>({}),[offset,setOffset]=useState(0),[selected,setSelected]=useState<Row|null>(null);
  const [criticality,setCriticality]=useState(''),[busy,setBusy]=useState(false),[notice,setNotice]=useState(''),[error,setError]=useState('');
  const params=new URLSearchParams({limit:String(size),offset:String(offset),...filters});
  const path='/'+kind+'?'+params.toString();
  const q=useQuery({queryKey:['monitor',user.user_id,user.role,path],queryFn:({signal})=>api<Row[]>(path,{signal}),refetchInterval:30000});
  const columns=cfg.columns.filter(c=>!(user.role==='viewer'&&kind==='alerts'&&c==='source_ip'));
  const id=selected?String(selected[cfg.id]):'';
  const detailPath=selected&&kind!=='events'&&!(kind==='alerts'&&user.role==='viewer')?'/'+kind+'/'+encodeURIComponent(id):'';
  const detail=useQuery({queryKey:['monitor',user.user_id,user.role,detailPath],queryFn:({signal})=>api<Row>(detailPath,{signal}),enabled:!!detailPath});
  function apply(e:FormEvent){e.preventDefault();setFilters(Object.fromEntries(Object.entries(draft).filter(([,v])=>v.trim()).map(([k,v])=>[k,v.trim()])));setOffset(0);setSelected(null);}
  function inspect(row:Row){setSelected(row);setCriticality(String(row.criticality??''));setError('');setNotice('');}
  async function updateCriticality(){if(!selected||busy||!['low','medium','high'].includes(criticality))return;if(!window.confirm('Change criticality for this endpoint?'))return;setBusy(true);setNotice('');setError('');try{const updated=await api<Row>('/devices/'+encodeURIComponent(id)+'/criticality',{method:'PATCH',body:JSON.stringify({criticality})});setSelected(updated);setNotice('Criticality updated.');await Promise.all([q.refetch(),detail.refetch()]);}catch(e){setError(e instanceof Error?e.message:'Update failed');}finally{setBusy(false);}}
  return <><div className="page-heading"><div><h1>{cfg.title}</h1><p className="muted">Live backend records · refreshes every 30 seconds</p></div><button disabled={q.isFetching} onClick={()=>void q.refetch()}>Refresh</button></div>
  <section className="panel"><form className="filter-form" onSubmit={apply}>{cfg.filters.map(k=><label key={k}>{label(k)}<input maxLength={255} value={draft[k]??''} placeholder="Exact match" onChange={e=>setDraft(d=>({...d,[k]:e.target.value}))}/></label>)}<button className="primary">Apply filters</button><button type="button" onClick={()=>{setDraft({});setFilters({});setOffset(0);setSelected(null);}}>Clear</button></form></section>
  <section className="panel">{q.isError?<p role="alert" className="error">{q.error.message}</p>:q.isPending?<p>Loading records…</p>:<Records rows={q.data??[]} columns={columns} id={cfg.id} onSelect={inspect}/>}<div className="pager"><button disabled={offset===0||q.isFetching} onClick={()=>{setOffset(n=>Math.max(0,n-size));setSelected(null);}}>Previous</button><span>Page {offset/size+1}</span><button disabled={q.isFetching||(q.data?.length??0)<size||offset>=100000} onClick={()=>{setOffset(n=>n+size);setSelected(null);}}>Next</button></div></section>
  {selected&&<section className="panel"><div className="page-heading"><h2>Selected {kind==='devices'?'endpoint':kind.slice(0,-1)}</h2><button disabled={busy} onClick={()=>setSelected(null)}>Close details</button></div>{detailPath&&detail.isError?<p role="alert" className="error">{detail.error.message}</p>:detailPath&&detail.isPending?<p>Loading details…</p>:<Fields row={Object.fromEntries(Object.entries(detailPath?(detail.data??selected):selected).filter(([k])=>!['alerts','history'].includes(k)))}/>}
  {kind==='events'&&<p className="muted">Normalized event metadata. Full raw log content is not exposed by this API.</p>}
  {kind==='devices'&&user.role==='administrator'&&<div className="filter-form"><label>Device criticality<select value={criticality} onChange={e=>setCriticality(e.target.value)} disabled={busy}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label><button disabled={busy||detail.isPending||detail.isError} onClick={()=>void updateCriticality()}>Save criticality</button>{notice&&<p role="status">{notice}</p>}{error&&<p role="alert" className="error">{error}</p>}</div>}
  {kind==='incidents'&&detail.data&&<><h2>Correlated alerts</h2><Records rows={Array.isArray(detail.data.alerts)?detail.data.alerts:[]} columns={['alert_id','rule_id','title','severity','status','overall_score','classification']} id="alert_id"/><h2>Incident history</h2><Records rows={Array.isArray(detail.data.history)?detail.data.history:[]} columns={['created_at','event_type','details']} id="history_id"/></>}
  </section>}
  {selected&&kind==='alerts'&&user.role!=='viewer'&&<><RemoteSection user={user} path={detailPath+'/risk'} title="Risk assessment"/><RemoteSection user={user} path={detailPath+'/ti'} title="Threat intelligence · linked provider results"/></>}
  </>;
}
