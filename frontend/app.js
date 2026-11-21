const T={trigger:{n:"Запуск",d:"Вручную или по расписанию",c:"#2f6b4f"},secrets:{n:"Поиск секретов",d:"Пароли и токены в файлах",c:"#b3261e"},sca:{n:"Анализ зависимостей",d:"SCA: известные CVE",c:"#d9622b"},sast:{n:"Статический анализ",d:"SAST: опасный код",c:"#7a5ac8"},condition:{n:"Условие",d:"Критичность, количество или регулярное выражение",c:"#c79a14"},ai:{n:"AI-рекомендации",d:"Объяснения и исправления",c:"#2d6cdf"},notify:{n:"Уведомление",d:"HTTP webhook",c:"#5a8bb5"}};
const SCANNERS=new Set(["secrets","sca","sast"]);
T.source={n:"Источник",d:"Файл или папка внутри ZIP",c:"#16767c"};
const SUPPORTED=new Set(["trigger","source","condition","ai","notify","custom",...SCANNERS]);
// Свои ноды: название, цвет и число портов хранятся в config. Порты с номерами («in2», «out3»)
// нужны только когда их больше одного, так же их проверяет бэкенд.
const NODE_COLORS=["#2f6b4f","#b3261e","#d9622b","#c79a14","#2d6cdf","#7a5ac8","#5a8bb5","#68766d"];
const isColor=c=>typeof c==="string"&&/^#[0-9a-fA-F]{6}$/.test(c);
const nodeName=n=>n.type==="custom"?(n.config?.title||"Своя нода"):(T[n.type]?.n||n.type);
const nodeColor=n=>n.type==="custom"?(isColor(n.config?.color)?n.config.color:"#68766d"):(T[n.type]?.c||"#68766d");
const nodeScanner=n=>n.type==="custom"?n.config?.scanner:SCANNERS.has(n.type)?n.type:null;
function ports(n){if(n.type==="custom")return{ins:(+n.config.inputs||1)+(nodeScanner(n)?1:0),outs:Math.max(0,+n.config.outputs||0)};
  return{ins:["trigger","source"].includes(n.type)?0:SCANNERS.has(n.type)?2:1,outs:n.type==="condition"?2:1}}
function outHandle(n,k){if(n.type==="condition")return k===1?"true":"false";return n.type==="custom"&&ports(n).outs>1?"out"+k:null}
function inHandle(n,k){
  if(nodeScanner(n)&&k===ports(n).ins)return "source";
  return n.type==="custom"&&n.config.inputs>1?"in"+k:null
}
function handleIndex(n,h){if(!h)return 1;if(h==="true")return 1;if(h==="false")return 2;if(h==="source")return ports(n).ins;return +h.replace(/\D/g,"")||1}
// заметка в ноде: до трёх строк примерно по 26 символов, остальное обрезается многоточием
function noteLines(n){const note=n.config?.note;return note?Math.min(3,Math.ceil(note.length/26)):0}
function nodeHeight(n){const p=ports(n),lines=noteLines(n);return Math.max(72,22*Math.max(p.ins,p.outs)+28)+(lines?lines*15+4:0)}
function portY(n,k,count){return Math.round(nodeHeight(n)*k/(count+1))}
const SEVRU={low:"низкая",medium:"средняя",high:"высокая",critical:"критичная"};
const REPORT_LEVELS={critical:"Критические",high:"Высокие",medium:"Средние",low:"Низкие"};
const RULES={
  "hardcoded-secret":"Секрет в коде",
  "vulnerable-dependency":"Уязвимая зависимость",
  "sql-injection":"Небезопасная сборка SQL",
  "tls-verification":"Ослабленная проверка TLS",
  "credentialed-cors":"Широкий CORS с учётными данными",
  "route-authorization":"Проверка доступа к маршруту",
  "object-authorization":"Проверка доступа к объекту",
  "python-dynamic-code":"Выполнение динамического кода Python",
  "python-shell":"Запуск команды через оболочку",
  "python-pickle":"Небезопасная десериализация Python",
  "js-dynamic-code":"Выполнение динамического JavaScript",
  "js-html-assignment":"Небезопасная вставка HTML"
};
const LLM_ERRORS={
  not_configured:"Модель не настроена на бэкенде.",
  bad_config:"Проверьте настройки модели на бэкенде.",
  auth_error:"Провайдер отклонил ключ API.",
  billing_error:"На аккаунте провайдера недостаточно средств.",
  rate_limited:"Провайдер ограничил частоту запросов. Попробуйте позже.",
  timeout:"Модель не ответила вовремя.",
  connection_error:"Не удалось подключиться к модели.",
  invalid_response:"Модель вернула некорректный ответ.",
  incomplete_response:"Модель не закончила ответ.",
  run_in_progress:"Дождитесь завершения проверки.",
  unknown_model:"Бэкенд больше не предлагает эту модель. Откройте настройки заново.",
  consent_required:"Подтвердите в настройках отправку находок в DeepSeek.",
  model_missing:"Выбранная модель не скачана на сервере моделей. Скачайте её или выберите другую в настройках.",
  no_api_key:"Для DeepSeek на бэкенде нужен DEEPSEEK_API_KEY.",
  http_error:"Эта версия бэкенда не поддерживает чат по отчёту."
};
const WEBHOOK_ERRORS={
  invalid_webhook_ref:"Выберите получателя в ноде «Уведомление».",
  invalid_webhook_settings:"Проверьте CYBER_GARDEN_WEBHOOKS на бэкенде.",
  webhook_not_configured:"Получатель удалён или не настроен на бэкенде.",
  webhook_timeout:"Получатель webhook не ответил вовремя.",
  webhook_connection_error:"Не удалось подключиться к получателю webhook."
};
const ERR={upload_too_large:"ZIP больше 10 МиБ. Загрузите архив поменьше.",project_too_large:"В архиве слишком много файлов или он слишком большой после распаковки (лимит 2000 файлов и 40 МиБ).",invalid_zip:"Не удалось прочитать архив. Загрузите ZIP без пароля.",invalid_zip_entry:"В архиве есть недопустимые или повторяющиеся пути. Пересоберите ZIP без ссылок и «..».",empty_project:"В архиве нет файлов проекта.",invalid_workflow:"Сценарий не прошёл проверку: нужен один запуск без входов, связи только между существующими нодами, без циклов, и каждая нода достижима из запуска.",unsupported_trigger:"Выберите ручной или ежедневный запуск.",invalid_schedule:"Проверьте время и часовой пояс расписания, например Europe/Moscow.",schedule_source_required:"Загрузите проект и закрепите его в настройках запуска.",invalid_node_config:"Проверьте настройки ноды.",invalid_condition:"Проверьте режим, критичность и порог в настройках условия.",invalid_condition_regex:"Введите корректное регулярное выражение RE2 до 160 символов. Обратные ссылки и проверки вперёд или назад не поддерживаются.",source_not_found:"Бэкенд не нашёл загруженный проект. Загрузите архив заново.",workflow_not_found:"Сценарий не найден на бэкенде.",run_not_found:"Запуск не найден на бэкенде.",invalid_request:"Бэкенд отклонил запрос из-за неверного поля."};
const $=s=>document.querySelector(s),esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
Object.assign(ERR,{
  invalid_scan_source:"Укажите относительный путь к файлу или папке внутри ZIP.",
  invalid_scan_source_edge:"Соедините один «Источник» с одноимённым входом сканера.",
  scan_source_not_found:"Файл или папка отсутствует в архиве.",
  template_owner_required:"Сохраните личный сценарий перед публикацией.",
  template_not_found:"Шаблон больше недоступен.",
  plugin_not_found:"Плагин больше недоступен.",
  plugin_limit_reached:"В аккаунте уже 100 плагинов. Удалите один, чтобы создать новый.",
  private_plugin_in_workflow:"Нода из приватного плагина доступна только в личном сценарии. Удалите её перед публикацией или сохранением в общем пространстве."
});
const ls={get:k=>{try{return localStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}}};
// локальная разработка: API на :8000; сайт через tools/serve_site.py: API на том же адресе под /api
const DEFAULT_API=["5173","3000"].includes(location.port)||location.protocol==="file:"?"http://127.0.0.1:8000":location.origin+"/api";
let API=ls.get("cg_api")||DEFAULT_API;
const accountTokenKey=()=>"cg_account_session:"+API;
let account=null;
async function api(path,opt){let r;
  const token=ss.get(accountTokenKey()),headers=new Headers(opt?.headers);
  if(token)headers.set("X-CodeBloodhound-Session",token);
  try{r=await fetch(API+path,{...opt,headers,redirect:token?"error":"follow"})}catch(e){throw{code:"network",message:`Нет связи с бэкендом (${API}). Проверьте, что uvicorn запущен и страница открыта с http://localhost:5173 или :3000: другие адреса бэкенд не пускает (CORS).`}}
  let b=null;try{b=await r.json()}catch(e){}
  if(!r.ok){let m=ERR[b?.code]||WEBHOOK_ERRORS[b?.code]||b?.message||"Ошибка "+r.status;
    if(b?.code==="unsupported_node"){const t=/The (\w+) node/.exec(b.message||"")?.[1];m=`Нода «${T[t]?.n||t}» пока не выполняется бэкендом. Уберите её из сценария, чтобы запустить.`}
    throw{code:b?.code||"http_"+r.status,message:ACCOUNT_ERRORS[b?.code]||m}}
  return b}
const JH={"Content-Type":"application/json"};
let wf={id:"",name:"Поиск секретов",nodes:[],edges:[]};
let sel=null,sourceId=null,sourceName="",report=null,pick=null,running=false,uid=1;
let historicalReport=false;
const pan={x:0,y:0};
const nid=()=>{let i;do{i="n"+uid++}while(wf.nodes.some(n=>n.id===i));return i};
const eid=()=>"e"+Math.random().toString(36).slice(2,9);
function mk(type,x,y,config){return{id:nid(),type,position:{x,y},config:config||{}}}
function init(){const a=mk("trigger",40,120,{mode:"manual"});wf.nodes=[a];const b=mk("secrets",270,120);wf.nodes.push(b);const c=mk("condition",500,120,{minSeverity:"high"});wf.nodes.push(c);
  wf.edges=[[a,b],[b,c]].map(([s,t])=>({id:eid(),source:s.id,target:t.id}))}
function toast(m){const t=$("#toast");t.textContent=m;t.style.display="block";clearTimeout(toast.h);toast.h=setTimeout(()=>t.style.display="none",5000)}
const fail=e=>toast(e.message||"Что-то пошло не так");
const stLabel=s=>({queued:"в очереди",running:"выполняется",succeeded:"готово",failed:"ошибка",skipped:"пропущена"}[s]);
// Ноды с находками или ошибками обводятся: красным при critical/high и ошибках, жёлтым при medium/low
// и при ответе без нейросети. По клику под холстом видно, что не так и что советует AI.
const SEV_RANK={critical:0,high:1,medium:2,low:3};
const worstSeverity=fs=>fs.reduce((a,f)=>SEV_RANK[f.severity]<SEV_RANK[a]?f.severity:a,"low");
function nodeError(n,s){const o=s.output||{};
  if(n.type==="source"&&ERR[o.errorCode])return ERR[o.errorCode];
  if(n.type==="notify"&&o.errorCode)return WEBHOOK_ERRORS[o.errorCode]||(o.statusCode?`Получатель вернул HTTP ${o.statusCode}.`:s.error);
  return s.error==="Node execution failed."?"Нода завершилась с ошибкой.":s.error||"Нода завершилась с ошибкой."}
function nodeIssues(n){const s=historicalReport?null:report?.nodes.find(x=>x.nodeId===n.id);if(!s||s.status==="running"||s.status==="queued")return null;
  const o=s.output||{},res={level:null,error:"",items:[],count:0};
  if(s.status==="failed"){res.level="bad";res.error=nodeError(n,s)}
  else if(n.type==="ai"&&o.aiAvailable===false){res.level="warn";res.error=(LLM_ERRORS[o.errorCode]||"Модель недоступна.")+(o.fallback?" Карточки собраны без нейросети.":"")}
  if(nodeScanner(n)){const ids=new Set((o.findings||[]).map(f=>f.id)),fs=(report.findings||[]).filter(f=>ids.has(f.id));
    res.count=fs.length;
    if(fs.length){res.level=res.level||(SEV_RANK[worstSeverity(fs)]<=1?"bad":"warn");
      const groups=report.aiAnalysis?.groups||[],buckets=new Map();
      for(const f of fs){const g=groups.find(x=>x.findingIds.includes(f.id)),key=g?"g:"+g.id:"r:"+f.ruleId;
        if(!buckets.has(key))buckets.set(key,{g,rule:f.ruleId,message:f.message,findings:[]});buckets.get(key).findings.push(f)}
      res.items=[...buckets.values()].map(b=>({...b,severity:worstSeverity(b.findings)})).sort((a,b)=>SEV_RANK[a.severity]-SEV_RANK[b.severity])}}
  return res.level?res:null}
function nodeIssuesBlock(){if(historicalReport||!report||sel?.t!=="n")return"";const n=wf.nodes.find(x=>x.id===sel.id);if(!n)return"";
  const s=report.nodes.find(x=>x.nodeId===n.id);if(!s||n.type==="trigger"||n.type==="condition")return"";
  const iss=nodeIssues(n);
  if(!iss)return s.status==="succeeded"?`<div class="node-issues ok"><h4>${esc(nodeName(n))}: проблем не найдено</h4></div>`:"";
  const label=r=>Object.hasOwn(RULES,r)?RULES[r]:r;
  return`<div class="node-issues ${iss.level}"><h4>Что не так: ${esc(nodeName(n))}${iss.count?` · ${plural(iss.count,"находка","находки","находок")}`:""}</h4>
    ${iss.error?`<p style="margin:0 0 6px">${esc(iss.error)}</p>`:""}
    ${iss.items.map(it=>`<div class="ni"><b><span class="sev ${esc(it.severity)}" aria-hidden="true"></span>${esc(it.g?.title||label(it.rule))}</b> <small>· ${SEVRU[it.severity]||esc(it.severity)} · ${plural(it.findings.length,"место","места","мест")}</small>
      <p>${esc(it.g?.explanation||it.message)}</p>${it.g?`<p><i>Что сделать:</i> ${esc(it.g.action)}</p>`:""}
      <ul>${it.findings.map(findingItem).join("")}</ul></div>`).join("")}</div>`}
function render(refreshInspector=true){
  const bd=$("#board");bd.querySelectorAll(".node").forEach(e=>e.remove());
  for(const n of wf.nodes){const e=document.createElement("div");e.className="node";e.dataset.id=n.id;
    const s=historicalReport?null:report?.nodes.find(x=>x.nodeId===n.id)?.status;if(s)e.classList.add("s-"+s);
    const iss=nodeIssues(n);if(iss){e.classList.add("alert-"+iss.level);e.title="Нажмите, чтобы увидеть, что не так"}
    const p=ports(n),note=n.config?.note;
    e.innerHTML=`<span class="bar" style="background:${nodeColor(n)}"></span><b>${esc(nodeName(n))}</b><div class="st"><span class="sdot"></span>${s?stLabel(s):SUPPORTED.has(n.type)?"ожидает запуска":"черновик, не запускается"}</div>`+
    (note?`<div class="nt" title="${esc(note)}" style="-webkit-line-clamp:${noteLines(n)};max-height:${noteLines(n)*15}px">${esc(note)}</div>`:"")+
    (iss?`<span class="badge" aria-label="Проблем: ${iss.count||1}">${iss.count||"!"}</span>`:"")+
    Array.from({length:p.ins},(_,i)=>{const handle=inHandle(n,i+1),isSource=handle==="source";
      return `<span class="h in${isSource?" scope-port":""}" data-in="${esc(n.id)}" data-hi="${handle||""}" style="top:${portY(n,i+1,p.ins)-7}px" title="${isSource?"Источник (необязательно)":handle?"Вход "+(i+1):"Вход потока"}"></span>`}).join("")+
    Array.from({length:p.outs},(_,i)=>{const h=outHandle(n,i+1),cls=h==="true"?"t":h==="false"?"f":"out",
      label=n.type==="source"?"Путь к файлу или папке":h==="true"?"Выход «да»":h==="false"?"Выход «нет»":"Выход"+(p.outs>1?" "+(i+1):"");
      return`<span class="h ${cls}" data-out="${esc(n.id)}" data-hd="${h||""}" style="top:${portY(n,i+1,p.outs)-7}px" title="${label}"></span>`}).join("");
    e.style.height=nodeHeight(n)+"px";
    if(sel?.t==="n"&&sel.id===n.id)e.classList.add("sel");
    placeNode(e,n);bd.appendChild(e)}
  edges();if(refreshInspector)inspector();if(report&&$("#repBody").dataset.issuesFor!==(sel?.t==="n"?sel.id:""))renderRep()}
function placeNode(element,node){
  element.style.setProperty("--node-x",node.position.x+"px");
  element.style.setProperty("--node-y",node.position.y+"px")
}
function pt(n,out,h){const p=n.position,c=ports(n);return out?[p.x+190,p.y+portY(n,handleIndex(n,h),c.outs)]:[p.x,p.y+portY(n,handleIndex(n,h),c.ins)]}
function edges(tmp){const sv=$("#edgeLayer");let h="";
  for(const e of wf.edges){const a=wf.nodes.find(n=>n.id===e.source),b=wf.nodes.find(n=>n.id===e.target);if(!a||!b)continue;
    const[x1,y1]=pt(a,1,e.sourceHandle),[x2,y2]=pt(b,0,e.targetHandle),dx=Math.max(40,(x2-x1)/2);
    const sourceResult=report?.nodes.find(x=>x.nodeId===e.source);
    const act=!historicalReport&&(sourceResult?.outputs?
      sourceResult.outputs.some(x=>x.nodeId===e.target&&x.port===(e.sourceHandle??null)):
      report?.nodes.find(x=>x.nodeId===e.target)?.status==="succeeded");
    // широкая прозрачная линия ловит клик, «×» в середине кривой удаляет связь одним нажатием
    const d=`M${x1},${y1} C${x1+dx},${y1} ${x2-dx},${y2} ${x2},${y2}`,mx=(x1+x2)/2,my=(y1+y2)/2;
    h+=`<g class="edge ${sel?.t==="e"&&sel.id===e.id?"on":""} ${act?"act":""}" data-e="${esc(e.id)}"><path class="hit" d="${d}"/><path class="line" d="${d}"/>`+
      (running?"":`<g class="edge-x" data-del="${esc(e.id)}" transform="translate(${mx},${my})"><title>Удалить связь</title><circle r="9"/><path d="M-3.5,-3.5L3.5,3.5M3.5,-3.5L-3.5,3.5"/></g>`)+`</g>`;
    if(e.sourceHandle)h+=`<text x="${x1+8}" y="${y1-6}">${e.sourceHandle==="true"?"да":e.sourceHandle==="false"?"нет":e.sourceHandle.slice(3)}</text>`}
  if(tmp)h+=`<path d="M${tmp[0]},${tmp[1]} L${tmp[2]},${tmp[3]}" style="stroke-dasharray:5 4;pointer-events:none"/>`;sv.innerHTML=h}
function cycle(s,t){const seen=new Set();const go=id=>{if(id===s)return true;if(seen.has(id))return false;seen.add(id);return wf.edges.filter(e=>e.source===id).some(e=>go(e.target))};return go(t)}
const bd=$("#board");
function setPan(x,y){
  pan.x=Math.round(x);pan.y=Math.round(y);
  bd.style.setProperty("--pan-x",pan.x+"px");bd.style.setProperty("--pan-y",pan.y+"px");
  $("#canvas").style.backgroundPosition=`${pan.x%22}px ${pan.y%22}px`
}
function visibleCanvas(){
  const width=bd.clientWidth,main=$("#main");
  const left=main.classList.contains("lib-open")?$("#left").offsetWidth:0;
  const right=main.classList.contains("ai-open")?$("#right").getBoundingClientRect().left-bd.getBoundingClientRect().left:width;
  return right-left>=220?{left,right}:{left:0,right:width}
}
function focusCanvas(){
  if(!wf.nodes.length)return setPan(0,0);
  const x=Math.min(...wf.nodes.map(n=>n.position.x));
  const y=Math.min(...wf.nodes.map(n=>n.position.y));
  setPan(visibleCanvas().left+40-x,60-y)
}
$("#canvasHome").onclick=focusCanvas;
function trackPointer(start,move,finish){
  const mv=e=>{if(e.pointerId===start.pointerId)move(e)};
  const end=e=>{if(e.pointerId!==start.pointerId)return;
    removeEventListener("pointermove",mv);removeEventListener("pointerup",end);removeEventListener("pointercancel",end);
    finish(e)
  };
  addEventListener("pointermove",mv);addEventListener("pointerup",end);addEventListener("pointercancel",end)
}
bd.addEventListener("wheel",e=>{if(e.ctrlKey||e.metaKey)return;e.preventDefault();
  const scale=e.deltaMode===1?16:e.deltaMode===2?bd.clientHeight:1;
  setPan(pan.x-e.deltaX*scale,pan.y-e.deltaY*scale)
},{passive:false});
bd.addEventListener("pointerdown",ev=>{
  if(ev.button!==0)return;
  const o=ev.target.closest("[data-out]"),nd=ev.target.closest(".node"),ep=ev.target.closest("[data-e]");
  if(!nd&&!ep){
    ev.preventDefault();sel=null;render();bd.classList.add("panning");
    const x=pan.x-ev.clientX,y=pan.y-ev.clientY;
    trackPointer(ev,e=>setPan(x+e.clientX,y+e.clientY),()=>bd.classList.remove("panning"));return
  }
  if(running)return;
  const del=ev.target.closest("[data-del]");
  if(del){ev.preventDefault();removeEdge(del.dataset.del);return}
  const r=bd.getBoundingClientRect();
  if(o){ev.preventDefault();const src=wf.nodes.find(n=>n.id===o.dataset.out),hd=o.dataset.hd||undefined,[x1,y1]=pt(src,1,hd);
    const mv=e=>edges([x1,y1,e.clientX-r.left-pan.x,e.clientY-r.top-pan.y]);
    const up=e=>{edges();if(e.type==="pointercancel")return;
      const t=document.elementFromPoint(e.clientX,e.clientY)?.closest("[data-in]");if(!t)return;const tid=t.dataset.in,hi=t.dataset.hi||undefined;
      if(tid===src.id)return toast("Нельзя соединить ноду с самой собой");
      if((src.type==="source")!==(hi==="source"))return toast("Соедините «Источник» с одноимённым входом сканера");
      if(hi==="source"&&wf.edges.some(x=>x.target===tid&&x.targetHandle==="source"))return toast("У сканера уже есть источник");
      if(wf.edges.some(x=>x.source===src.id&&x.target===tid&&(x.sourceHandle??undefined)===hd&&(x.targetHandle??undefined)===hi))return toast("Такая связь уже есть");
      if(cycle(src.id,tid))return toast("Циклы запрещены: связь замкнёт сценарий");
      wf.edges.push({id:eid(),source:src.id,target:tid,...(hd?{sourceHandle:hd}:{}),...(hi?{targetHandle:hi}:{})});clearReport()};
    trackPointer(ev,mv,up);return}
  if(nd&&!ev.target.closest("[data-in]")){const n=wf.nodes.find(x=>x.id===nd.dataset.id);sel={t:"n",id:n.id};
    const ox=ev.clientX-pan.x-n.position.x,oy=ev.clientY-pan.y-n.position.y;
    const mv=e=>{n.position.x=Math.round(e.clientX-pan.x-ox);n.position.y=Math.round(e.clientY-pan.y-oy);placeNode(nd,n);edges()};
    trackPointer(ev,mv,render);document.querySelectorAll(".node.sel").forEach(x=>x.classList.remove("sel"));nd.classList.add("sel");inspector();
    if(report&&nodeIssues(n))openRep();return}
  if(ep){// второй клик по той же связи в течение 400 мс удаляет её: dblclick теряется, потому что первый клик перерисовывает связи
    const id=ep.dataset.e,now=Date.now();
    if(lastEdgeClick.id===id&&now-lastEdgeClick.t<400){lastEdgeClick={};removeEdge(id);return}
    lastEdgeClick={id,t:now};sel={t:"e",id};render();return}
  sel=null;render()});
addEventListener("keydown",e=>{if(["INPUT","SELECT","TEXTAREA"].includes(e.target.tagName))return;if((e.key==="Delete"||e.key==="Backspace")&&sel)del()});
let lastEdgeClick={};
function removeEdge(id){if(running)return;wf.edges=wf.edges.filter(e=>e.id!==id);if(sel?.t==="e"&&sel.id===id)sel=null;clearReport();toast("Связь удалена")}
function clearReport(refreshInspector=true){report=null;historicalReport=false;pick=null;render(refreshInspector);renderRep();renderAI()}
function del(){if(!sel||running)return;if(sel.t==="n"){wf.nodes=wf.nodes.filter(n=>n.id!==sel.id);wf.edges=wf.edges.filter(e=>e.source!==sel.id&&e.target!==sel.id)}else wf.edges=wf.edges.filter(e=>e.id!==sel.id);sel=null;clearReport()}
let webhookRefs=[],webhookListError="";
function webhookInspector(selected){
  const refs=webhookRefs.map(ref=>`<option value="${esc(ref)}">${esc(ref)}</option>`).join("");
  const missing=selected&&!webhookRefs.includes(selected)
    ?`<option value="${esc(selected)}">${esc(selected)} (нет в списке)</option>`:"";
  const note=webhookListError||(!refs
    ?"Добавьте получателя через CYBER_GARDEN_WEBHOOKS на бэкенде."
    :"Получатель получит находки и AI-рекомендации с этой ветки в JSON.");
  return `<label class="f" for="webhookRef">Получатель</label>
    <select id="webhookRef" data-k="webhookRef"><option value="">Выберите получателя</option>${refs}${missing}</select>
    <p class="note">${esc(note)}</p>`;
}
const CONDITION_DEFAULTS={conditionMode:"severity",minSeverity:"high",countMinSeverity:"low",comparison:"ge",threshold:1,field:"file"};
const TRIGGER_DEFAULTS={mode:"manual",scheduleTime:"09:00",scheduleTimezone:Intl.DateTimeFormat().resolvedOptions().timeZone||"UTC"};
function triggerInspector(config){
  const select=`<label class="f" for="triggerMode">Режим</label><select id="triggerMode" data-k="mode">
    <option value="manual">Вручную</option><option value="daily">Каждый день</option></select>`;
  if(config.mode!=="daily")return select+`<p class="note">Нажмите «Запустить», чтобы проверить проект, выбранный над холстом.</p>`;
  const name=config.scheduleSourceName||(config.scheduleSourceId?"Проект закреплён":"Проект не закреплён");
  return select+`<label class="f" for="scheduleTime">Время запуска</label><input id="scheduleTime" type="time" data-k="scheduleTime" step="60">
    <label class="f" for="scheduleTimezone">Часовой пояс</label><input id="scheduleTimezone" type="text" data-k="scheduleTimezone" placeholder="Europe/Moscow" maxlength="100">
    <p class="note"><b>${esc(name)}</b></p><button class="btn" id="bindSchedule" ${sourceId&&!running?"":"disabled"}>Закрепить загруженный проект</button>
    <p class="note">Сохраните сценарий, чтобы включить расписание. Будет проверяться эта загруженная версия проекта.</p>`
}
function conditionInspector(config){
  const optionList=options=>Object.entries(options).map(([value,label])=>`<option value="${value}">${label}</option>`).join("");
  const select=(key,label,options)=>`<label class="f" for="${key}">${label}</label><select id="${key}" data-k="${key}">${optionList(options)}</select>`;
  let html=select("conditionMode","Проверка",{severity:"Критичность",count:"Количество находок",regex:"Регулярное выражение"});
  if(config.conditionMode==="count"){
    html+=select("countMinSeverity","Учитывать находки",{...SEVRU,low:"любой критичности"});
    html+=select("comparison","Сравнение",{eq:"Равно",ne:"Не равно",lt:"Меньше",le:"Меньше или равно",gt:"Больше",ge:"Больше или равно"});
    return html+`<label class="f" for="threshold">Порог</label><input id="threshold" type="number" data-k="threshold" min="0" step="1">`
  }
  if(config.conditionMode==="regex"){
    html+=select("field","Поле находки",{file:"Путь к файлу",ruleId:"Код правила",message:"Описание",cve:"CVE",advisoryId:"Advisory ID"});
    return html+`<label class="f" for="pattern">Регулярное выражение</label><input id="pattern" type="text" data-k="pattern" maxlength="160" spellcheck="false">
      <p class="note">Выход «Да» срабатывает, если выражение совпало хотя бы с одной находкой.</p>`
  }
  return html+select("minSeverity","Минимальная критичность",SEVRU)+`<p class="note">Выход «Да» срабатывает, если есть находка этой критичности или выше.</p>`
}
function scannerOptions(selected){
  const options=[["","Передача находок"],...Array.from(SCANNERS,id=>[id,T[id].n])];
  return options.map(([id,name])=>`<option value="${id}"${id===(selected??"")?" selected":""}>${name}</option>`).join("")
}
const supportsLanguage=scanner=>scanner==="secrets"||scanner==="sast";
function languageOptions(selected){
  const options=[["","Языки сценария"],...Object.entries(PLUGIN_NAMES)];
  return options.map(([id,name])=>`<option value="${id}"${id===(selected??"")?" selected":""}>${name}</option>`).join("")
}
function inspector(){document.querySelector(".insp")?.remove();if(!sel)return;
  const box=document.createElement("div");box.className="insp";let h="";
  if(sel.t==="e")h=`<h3>Связь</h3><p class="note">Удалить связь можно кнопкой «×» на ней, двойным кликом или клавишей Delete.</p><button class="btn" id="delSel" style="margin-top:8px">Удалить связь</button>`;
  else{const n=wf.nodes.find(x=>x.id===sel.id),c=n.config;h=`<h3>${esc(nodeName(n))}</h3>`;
    if(n.type==="custom")h+=`<label class="f">Название</label><input type="text" data-c="title" maxlength="40" value="${esc(c.title||"")}">
      <label class="f" for="customScanner">Действие</label><select id="customScanner" data-c="scanner">${scannerOptions(c.scanner)}</select>
      ${supportsLanguage(c.scanner)?`<label class="f" for="customLanguage">Язык проверки</label><select id="customLanguage" data-c="language">${languageOptions(c.language)}</select>`:""}
      <div class="ports"><div><label class="f">Входов</label><select data-c="inputs">${[1,2,3,4].map(v=>`<option ${v===+c.inputs?"selected":""}>${v}</option>`).join("")}</select></div>
      <div><label class="f">Выходов</label><select data-c="outputs">${[0,1,2,3,4].map(v=>`<option ${v===+c.outputs?"selected":""}>${v}</option>`).join("")}</select></div></div>
      <label class="f">Цвет</label><div class="swatches">${NODE_COLORS.map(col=>`<button type="button" data-col="${col}" class="${col===c.color?"on":""}" style="background:${col}" aria-label="Цвет ${col}"></button>`).join("")}<input type="color" data-c="color" value="${isColor(c.color)?c.color:"#68766d"}" aria-label="Свой цвет"></div>
      <p class="note">Передаёт входящие и собственные находки на все выходы. Связи с удалёнными портами исчезнут.</p>`;
    if(n.type==="trigger")h+=triggerInspector(c);
    else if(n.type==="source")h+=`<label class="f" for="sourcePath">Относительный путь в ZIP</label><input id="sourcePath" data-k="path" type="text" maxlength="500" placeholder="src/main или app.py">
      <p class="note">Соедините выход с портом «Источник» одного или нескольких сканеров.</p>`;
    else if(n.type==="condition")h+=conditionInspector(c);
    else if(n.type==="secrets")h+=`<p class="note">Ищет пароли, токены и ключи в коде и конфигурации. В отчёте указывает файл и строку без значения секрета.</p>`;
    else if(n.type==="sca")h+=`<p class="note">Сверяет версии зависимостей Gradle со справочником Maven. Справочник берётся из архива или из настроек сервера.</p>`;
    else if(n.type==="sast")h+=`<p class="note">Проверяет Kotlin и языки подключённых плагинов по правилам статического анализа.</p>`;
    else if(n.type==="ai")h+=`<p class="note">Объясняет находки и предлагает исправления. Модель выбирается в настройках редактора. При сбое модели отчёт показывает подсказки по правилам сканеров.</p>`;
    else if(n.type==="notify")h+=webhookInspector(c.webhookRef);
    else if(n.type==="custom");  // настройки своей ноды выведены выше
    else h+=`<p class="note">Бэкенд пока не умеет выполнять эту ноду. Её можно сохранить в сценарии как черновик, но запуск такого сценария будет отклонён.</p>`;
    if(nodeScanner(n))h+=`<p class="note">Без связи на входе «Источник» проверяется весь ZIP.</p>`;
    if(supportsLanguage(nodeScanner(n))&&!c.language){
      const plugins=(wf.id?wf.languagePlugins:account?.languagePlugins)||[];
      if(plugins.length)h+=`<p class="note">Языковые плагины: ${esc(plugins.map(id=>PLUGIN_NAMES[id]).join(", "))}.</p>`
    }
    if(n.type!=="trigger")h+=`<label class="f" for="nodeNote">Заметка</label><textarea id="nodeNote" maxlength="1000" placeholder="Что проверить или кто отвечает">${esc(c.note||"")}</textarea>
      ${n.config.privatePluginOwner?"":`<button class="btn" id="saveTpl" style="margin-top:8px">Сохранить в каталоге</button>`}
      ${n.type==="custom"?`<button class="btn" id="savePlugin" style="margin-top:8px">Сохранить как плагин</button>`:""}`;
    h+=`<button class="btn" id="delSel" style="margin-top:10px">Удалить ноду</button>`}
  box.innerHTML=h;$(".canvas").appendChild(box);box.addEventListener("pointerdown",e=>e.stopPropagation());
  box.querySelectorAll("[data-k]").forEach(el=>{const n=wf.nodes.find(x=>x.id===sel.id),key=el.dataset.k;
    el.value=Object.hasOwn(n.config,key)?n.config[key]??"":CONDITION_DEFAULTS[key]??TRIGGER_DEFAULTS[key]??"";
    el.disabled=running;
    el.onchange=()=>{
      n.config[key]=el.type==="number"?(el.value===""?null:Number(el.value)):key==="path"?el.value.trim():el.value;
      if(key==="conditionMode"){
        const keys={severity:["minSeverity"],count:["countMinSeverity","comparison","threshold"],regex:["field"]}[el.value];
        for(const name of keys){if(!Object.hasOwn(n.config,name))n.config[name]=CONDITION_DEFAULTS[name]}
      }
      if(key==="mode"&&el.value==="daily"){
        n.config.scheduleTime??=TRIGGER_DEFAULTS.scheduleTime;
        n.config.scheduleTimezone??=TRIGGER_DEFAULTS.scheduleTimezone
      }
      clearReport(key==="conditionMode"||key==="mode")
    }});
  const node=sel.t==="n"&&wf.nodes.find(x=>x.id===sel.id);
  if(node){const note=box.querySelector("#nodeNote");
    box.querySelector("#bindSchedule")?.addEventListener("click",()=>{
      if(!sourceId||running)return;
      node.config.scheduleSourceId=sourceId;node.config.scheduleSourceName=sourceName;
      clearReport()
    });
    if(note){note.disabled=running;note.oninput=()=>{node.config.note=note.value};note.onchange=()=>{note.value=note.value.trim();node.config.note=note.value;if(!node.config.note)delete node.config.note;render(false)}}
    box.querySelector("#saveTpl")?.addEventListener("click",()=>saveTemplate(node));
    box.querySelector("#savePlugin")?.addEventListener("click",()=>openPluginEditor({config:node.config}));
    box.querySelectorAll("[data-c]").forEach(el=>{el.disabled=running;el.onchange=()=>{const k=el.dataset.c;
      const before={...node,config:{...node.config}};
      node.config[k]=k==="inputs"||k==="outputs"?+el.value:k==="title"?(el.value.trim()||"Своя нода"):el.value;
      if(k==="scanner"){
        if(!el.value)delete node.config.scanner;
        if(!supportsLanguage(el.value))delete node.config.language
      }
      if(k==="language"&&!el.value)delete node.config.language;
      if(k==="inputs"||k==="outputs"||k==="scanner")updateCustomEdges(node,before);
      clearReport()}});
    box.querySelectorAll("[data-col]").forEach(b=>b.onclick=()=>{if(running)return;node.config.color=b.dataset.col;render()})}
  $("#delSel").onclick=del}
function updateCustomEdges(node,before){
  const outs=Array.from({length:ports(node).outs},(_,i)=>outHandle(node,i+1));
  const ins=Array.from({length:ports(node).ins},(_,i)=>inHandle(node,i+1));
  wf.edges=wf.edges.filter(edge=>{
    if(edge.source===node.id){
      const index=handleIndex(before,edge.sourceHandle)-1;
      if(index>=outs.length)return false;
      edge.sourceHandle=outs[index]??undefined
    }
    if(edge.target===node.id){
      if(edge.targetHandle==="source")return ins.includes("source");
      const index=handleIndex(before,edge.targetHandle)-1;
      if(index>=node.config.inputs)return false;
      edge.targetHandle=ins[index]??undefined
    }
    return true
  })
}
async function saveTemplate(n){const note=(n.config.note||"").trim();
  const name=(nodeName(n)+(note&&n.type!=="custom"?" — "+note:"")).slice(0,60);
  const {note:_,...rest}=n.config,config=note?{...rest,note}:rest;
  try{await api("/node-templates",{method:"POST",headers:JH,body:JSON.stringify({name,type:n.type,config})});
    toast("Нода сохранена в «Сохранённые»");if(tab==="cat"&&libTab==="saved")left()}catch(e){fail(e)}}
// левая панель
let tab="cat";
let libTab="std";
function setNodeCatalog(open){
  $("#main").classList.toggle("lib-open",open);
  $("#nodeCatalogBtn").setAttribute("aria-expanded",String(open))
}
function addNode(type,config){if(running)return toast("Дождитесь завершения проверки");
  if(type==="trigger"&&wf.nodes.some(n=>n.type==="trigger"))return toast("В сценарии только один запуск");
  setNodeCatalog(false);
  const n=mk(type,0,0,config),height=nodeHeight(n);
  const view=visibleCanvas();
  const x=Math.round((view.left+view.right)/2-pan.x-95),y=Math.round(bd.clientHeight/2-pan.y-height/2);
  n.position={x,y};
  while(wf.nodes.some(existing=>Math.abs(existing.position.x-x)<206&&
    n.position.y<existing.position.y+nodeHeight(existing)+16&&n.position.y+height+16>existing.position.y)){
    n.position.y+=height+16
  }
  if(n.position.y+pan.y+height>bd.clientHeight)setPan(pan.x,Math.round(bd.clientHeight/2-n.position.y-height/2));
  wf.nodes.push(n);sel={t:"n",id:n.id};clearReport();return n}
function portsText(c){return`${plural(+c.inputs||1,"вход","входа","входов")}, ${plural(+c.outputs||0,"выход","выхода","выходов")}`}
function left(){const l=$("#leftList");
  if(tab==="my")return loadMy();
  const head=`<div class="seg" role="tablist"><button role="tab" data-lib="std" class="${libTab==="std"?"on":""}">Стандартные</button><button role="tab" data-lib="saved" class="${libTab==="saved"?"on":""}">Сохранённые</button></div>
    <button class="cat new" id="newNode">＋ Создать свою ноду</button>`;
  if(libTab==="std")l.innerHTML=head+Object.entries(T).map(([k,t])=>`<button class="cat" data-add="${k}"><span class="dot" style="background:${t.c}"></span><span>${t.n}<small>${t.d}${SUPPORTED.has(k)?"":" (пока черновик)"}</small></span></button>`).join("");
  else{l.innerHTML=head+`<div class="empty">Загрузка…</div>`;loadTemplates()}
  l.querySelectorAll("[data-lib]").forEach(b=>b.onclick=()=>{libTab=b.dataset.lib;left()});
  $("#newNode").onclick=()=>openNodeDialog();
  l.querySelectorAll("[data-add]").forEach(b=>b.onclick=()=>{const k=b.dataset.add;addNode(k,k==="condition"?{minSeverity:"high"}:k==="trigger"?{mode:"manual"}:k==="source"?{path:"."}:{})})}
async function loadTemplates(){const l=$("#leftList"),loading=l.querySelector(".empty");
  let templates;
  try{templates=await api("/node-templates")}catch(e){if(loading.isConnected)loading.textContent=e.message||"Не удалось загрузить сохранённые ноды";return}
  if(!loading.isConnected)return;
  loading.remove();
  l.insertAdjacentHTML("beforeend",`<p class="note" style="margin:0">Общая библиотека: сохранённые ноды видны всей команде.</p>`+(templates.length?templates.map((t,i)=>{const n={type:t.type,config:t.config||{}};
    const info=t.type==="custom"?"своя нода · "+portsText(n.config):nodeName(n)+(n.config.note?" · с текстом":"");
    return`<div class="cat-row"><button class="cat" data-tpl="${i}"><span class="dot" style="background:${nodeColor(n)}"></span><span style="min-width:0;flex:1"><span style="display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(t.name)}">${esc(t.name)}</span><small style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(info)}</small></span></button><button class="x" data-rm="${i}" title="Удалить из сохранённых" aria-label="Удалить «${esc(t.name)}» из сохранённых">×</button></div>`}).join("")
    :`<div class="empty">Пока пусто. Создайте свою ноду или откройте ноду на холсте и нажмите «Сохранить ноду».</div>`));
  l.querySelectorAll("[data-tpl]").forEach(b=>b.onclick=()=>{const t=templates[b.dataset.tpl];addNode(t.type,JSON.parse(JSON.stringify(t.config||{})))});
  l.querySelectorAll("[data-rm]").forEach(b=>b.onclick=async()=>{const t=templates[b.dataset.rm];
    try{await api(`/node-templates/${encodeURIComponent(t.id)}/remove`,{method:"POST"});toast("Удалено из сохранённых");left()}catch(e){fail(e)}})}
let cnColor=NODE_COLORS[4],nodeEditor=null;
function paintSwatches(){const box=$("#cnColors");
  box.innerHTML=NODE_COLORS.map(c=>`<button type="button" data-col="${c}" class="${c===cnColor?"on":""}" style="background:${c}" aria-label="Цвет ${c}"></button>`).join("")+`<input type="color" id="cnCustom" value="${cnColor}" aria-label="Свой цвет">`;
  box.querySelectorAll("[data-col]").forEach(b=>b.onclick=()=>{cnColor=b.dataset.col;paintSwatches()});
  $("#cnCustom").oninput=e=>{cnColor=e.target.value;box.querySelectorAll("[data-col]").forEach(b=>b.classList.toggle("on",b.dataset.col===cnColor))}}
function openNodeDialog({pluginMode=false,plugin=null,config={}}={}){
  if(running)return toast("Дождитесь завершения проверки");
  nodeEditor={pluginMode,id:plugin?.id,owner:account?.id,origin:API};
  $("#cnHeading").textContent=plugin?.id?"Редактировать плагин":pluginMode?"Создать плагин":"Своя нода";
  $("#cnTitle").value=config.title||"";$("#cnNote").value=config.note||"";
  $("#cnIn").value=config.inputs??1;$("#cnOut").value=config.outputs??1;
  $("#cnScanner").innerHTML=scannerOptions(config.scanner);
  $("#cnLanguage").innerHTML=languageOptions(config.language);
  $("#cnLanguageRow").hidden=!supportsLanguage(config.scanner);
  $("#cnSave").checked=true;$("#cnSaveRow").hidden=pluginMode;
  $("#cnPluginFields").hidden=!pluginMode;
  $("#cnDescription").required=pluginMode;$("#cnDescription").value=plugin?.description||"";
  $("#cnVisibility").value=plugin?.visibility||"private";
  $("#cnPublicNote").hidden=$("#cnVisibility").value!=="public";
  $("#cnStatus").textContent="";
  $("#cnCreate").disabled=false;
  $("#cnCreate").textContent=pluginMode?"Сохранить плагин":"Добавить на холст";
  cnColor=isColor(config.color)?config.color:NODE_COLORS[4];paintSwatches();
  $("#ovNode").classList.add("open");$("#cnTitle").focus()
}
function openPluginEditor({plugin=null,config=plugin?.config||{}}={}){
  if(!account){
    toast("Войдите, чтобы сохранить свой плагин.");
    if(!running&&!sourceLoading)openAccountDialog("login");
    return
  }
  openNodeDialog({pluginMode:true,plugin,config})
}
$("#cnScanner").onchange=event=>{
  const languageRow=$("#cnLanguageRow");
  languageRow.hidden=!supportsLanguage(event.target.value);
  if(languageRow.hidden)$("#cnLanguage").value=""
};
$("#cnVisibility").onchange=event=>$("#cnPublicNote").hidden=event.target.value!=="public";
$("#customNodeForm").onsubmit=async event=>{
  event.preventDefault();
  const edit=nodeEditor,button=$("#cnCreate"),status=$("#cnStatus");
  if(!edit||button.disabled)return;
  const title=$("#cnTitle").value.trim(),note=$("#cnNote").value.trim(),scanner=$("#cnScanner").value;
  if(!title){status.textContent="Введите название ноды.";$("#cnTitle").focus();return}
  const language=supportsLanguage(scanner)?$("#cnLanguage").value:"";
  const config={title,color:cnColor,inputs:+$("#cnIn").value,outputs:+$("#cnOut").value};
  if(note)config.note=note;
  if(scanner)config.scanner=scanner;
  if(language)config.language=language;
  if(edit.pluginMode){
    if(edit.owner!==account?.id||edit.origin!==API)return;
    const description=$("#cnDescription").value.trim();
    if(!description){status.textContent="Добавьте описание плагина.";$("#cnDescription").focus();return}
    const visibility=$("#cnVisibility").value,path=edit.id?"/plugins/"+encodeURIComponent(edit.id):"/plugins";
    button.disabled=true;status.textContent="";
    try{
      await api(path,{method:edit.id?"PUT":"POST",headers:JH,body:JSON.stringify({config,description,visibility})});
      if(edit.owner!==account?.id||edit.origin!==API)return;
      if(nodeEditor===edit)$("#ovNode").classList.remove("open");
      if(libraryOpen()&&librarySection==="plugins")loadPluginLibrary();
      toast("Плагин сохранён.")
    }catch(error){if(nodeEditor===edit)status.textContent=error.message}
    finally{if(nodeEditor===edit)button.disabled=false}
    return
  }
  if(!addNode("custom",{...config}))return;
  $("#ovNode").classList.remove("open");
  if($("#cnSave").checked){try{await api("/node-templates",{method:"POST",headers:JH,body:JSON.stringify({name:title,type:"custom",config})});toast("Нода добавлена и сохранена");if(tab==="cat"&&libTab==="saved")left()}catch(error){fail(error)}}
};
async function loadMy(){const l=$("#leftList");l.innerHTML=`<div class="empty">Загрузка…</div>`;
  const token=ss.get(accountTokenKey()),origin=API;
  try{const list=await api("/workflows");
    if(tab!=="my"||token!==ss.get(accountTokenKey())||API!==origin)return;
    l.innerHTML=list.length?list.map((s,i)=>`<button class="cat" data-i="${i}"><span>${esc(s.name)}<small>${s.languagePlugins?"Личный сценарий":"Общий сценарий"}</small></span></button>`).join(""):`<div class="empty">Сохранённых сценариев пока нет. Откройте «Файл» → «Сохранить».</div>`;
    l.querySelectorAll("[data-i]").forEach(b=>b.onclick=()=>{if(running)return toast("Дождитесь завершения проверки");wf=JSON.parse(JSON.stringify(list[b.dataset.i]));wf.nodes.forEach(n=>n.config=n.config||{});$("#wfName").value=wf.name;sel=null;focusCanvas();clearReport()})}
  catch(e){if(tab==="my"&&token===ss.get(accountTokenKey())&&API===origin)l.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>{tab=b.dataset.t;document.querySelectorAll(".tabs button").forEach(x=>x.classList.toggle("on",x===b));left()});
// сохранение
async function save(){const current=wf;current.name=$("#wfName").value.trim()||"Без названия";
  const r=await api(current.id?"/workflows/"+current.id:"/workflows",{method:current.id?"PUT":"POST",headers:JH,body:JSON.stringify({name:current.name,nodes:current.nodes,edges:current.edges})});
  current.id=r.id;current.languagePlugins=r.languagePlugins;return r}
$("#fileBtn").onclick=e=>{e.stopPropagation();$("#fileMenu").classList.toggle("open")};
addEventListener("click",()=>$("#fileMenu").classList.remove("open"));
$("#fileMenu").querySelectorAll("[data-a]").forEach(b=>b.onclick=async()=>{const a=b.dataset.a;
  if(running&&a!=="dl")return toast("Дождитесь завершения проверки");
  if(a==="generate")return openGenerator();
  if(a==="new"){wf={id:"",name:"Новый сценарий",nodes:[],edges:[]};$("#wfName").value=wf.name;sel=null;focusCanvas();clearReport()}
  if(a==="dl"){const{id,...d}=wf;d.name=$("#wfName").value;$("#jsonOut").value=JSON.stringify(d,null,2);$("#ovJson").classList.add("open")}
  if(a==="save"){try{await save();toast("Сценарий сохранён");if(tab==="my")left()}catch(e){fail(e)}}});
$("#jsonCopy").onclick=async()=>{try{await navigator.clipboard.writeText($("#jsonOut").value);toast("JSON скопирован")}catch(e){$("#jsonOut").select();toast("Выделено — скопируйте вручную")}};
function downloadJson(filename,text){
  const url=URL.createObjectURL(new Blob([text],{type:"application/json;charset=utf-8"}));
  const link=document.createElement("a");link.href=url;link.download=filename;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000)
}
$("#jsonDownload").onclick=()=>downloadJson("workflow.json",$("#jsonOut").value);
document.querySelectorAll("[data-close]").forEach(b=>b.onclick=()=>b.closest(".ov").classList.remove("open"));
// Генерация создаёт отдельный черновик и меняет граф только по кнопке «Открыть».
let generation=null;
function resetGenerationPreview(){
  $("#generatePreview").hidden=true;
  $("#generateApply").hidden=true;
  generation.draft=null
}
function openGenerator(){
  generation={pending:false,draft:null};
  $("#generateStatus").textContent="";
  $("#generateConsent").checked=false;
  $("#generateConsentRow").hidden=!activeModel()?.startsWith("deepseek:");
  $("#generateRun").disabled=false;
  $("#generatePrompt").disabled=false;
  resetGenerationPreview();
  $("#ovGenerate").classList.add("open");
  $("#generatePrompt").focus()
}
$("#generatePrompt").oninput=()=>{
  if(generation?.draft){
    resetGenerationPreview();
    $("#generateStatus").textContent=""
  }
};
$("#generateForm").onsubmit=async event=>{
  event.preventDefault();
  const current=generation,description=$("#generatePrompt").value.trim(),status=$("#generateStatus");
  if(!current||current.pending||!description)return;
  const allowExternal=$("#generateConsent").checked,modelId=activeModel();
  if(!$("#generateConsentRow").hidden&&!allowExternal){
    status.textContent="Подтвердите отправку описания в DeepSeek.";
    return
  }
  resetGenerationPreview();
  current.pending=true;
  $("#generateRun").disabled=true;$("#generatePrompt").disabled=true;
  status.textContent="Генерируем черновик…";
  try{
    const result=await api("/workflows/generate",{method:"POST",headers:JH,body:JSON.stringify({
      description,modelId,allowExternal,timezone:TRIGGER_DEFAULTS.scheduleTimezone
    })});
    if(generation!==current||!$("#ovGenerate").classList.contains("open"))return;
    current.draft=result.draft;
    $("#generateName").textContent=result.draft.name;
    $("#generateNodes").textContent=result.draft.nodes.map(nodeName).join(" · ");
    const warnings=$("#generateWarnings");
    warnings.replaceChildren();
    if(result.needsSource){
      const trigger=result.draft.nodes.find(n=>n.type==="trigger");
      const item=document.createElement("li");
      item.textContent=`Запуск ежедневно в ${trigger.config.scheduleTime} (${trigger.config.scheduleTimezone}). Закрепите загруженный проект в ноде «Запуск».`;
      warnings.append(item)
    }
    if(result.needsRecipient){
      const item=document.createElement("li");
      item.textContent="Выберите получателя в ноде «Уведомление».";
      warnings.append(item)
    }
    $("#generatePreview").hidden=false;$("#generateApply").hidden=false;
    status.textContent="Черновик готов."
  }catch(error){
    if(generation!==current||!$("#ovGenerate").classList.contains("open"))return;
    if(error.code==="consent_required")$("#generateConsentRow").hidden=false;
    status.textContent=({
      consent_required:"Подтвердите отправку описания в DeepSeek.",
      unsupported_generation:"Опишите проверку учебного проекта. Доступны поиск секретов, SCA и SAST, ручной и ежедневный запуск.",
      invalid_response:"Модель не смогла составить корректный сценарий. Уточните описание и повторите."
    })[error.code]||LLM_ERRORS[error.code]||error.message
  }finally{
    current.pending=false;
    if(generation===current){$("#generateRun").disabled=false;$("#generatePrompt").disabled=false}
  }
};
$("#generateApply").onclick=()=>{
  if(running||!generation?.draft)return;
  wf={...generation.draft,id:""};
  $("#wfName").value=wf.name;sel=null;focusCanvas();clearReport();
  $("#ovGenerate").classList.remove("open")
};
// связь с бэкендом и настройки
async function loadWebhookRefs(){
  const origin=API;
  let refs=[],error="";
  try{refs=await api("/webhooks")}
  catch(e){error=WEBHOOK_ERRORS[e.code]||"Не удалось загрузить список получателей."}
  if(origin!==API)return;
  webhookRefs=Array.isArray(refs)?refs:[];
  webhookListError=error;
  if(sel?.t==="n"&&wf.nodes.some(n=>n.id===sel.id&&n.type==="notify"))inspector()
}
async function ping(){const t=$("#apiTag");try{await api("/health");t.textContent="бэкенд на связи";t.classList.add("ok");loadWebhookRefs();return true}catch(e){t.textContent="нет связи с бэкендом";t.classList.remove("ok");webhookRefs=[];webhookListError="Нет связи с бэкендом.";inspector();return false}}
// выбор модели: у каждой вкладки свой (sessionStorage), модель уходит с каждым запуском и вопросом в чате
let llmSettings=null;
const PROVIDERS={local:"локальная",deepseek:"DeepSeek API"};
const ss={get:k=>{try{return sessionStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{v==null?sessionStorage.removeItem(k):sessionStorage.setItem(k,v)}catch(e){}}};
const PLUGIN_NAMES={python:"Python",javascript:"JavaScript и TypeScript"};
const ACCOUNT_ERRORS={
  account_required:"Войдите, чтобы управлять языковыми плагинами.",
  invalid_session:"Сессия истекла. Войдите заново.",
  invalid_credentials:"Неверное имя пользователя или пароль.",
  username_taken:"Это имя пользователя уже занято.",
  registration_conflict:"Такое имя пользователя или почта уже используются.",
  password_mismatch:"Пароли не совпадают."
};
let accountMode="login",accountPending=false;
const accountMenu=$("#accountMenu"),accountButton=$("#accountBtn"),accountDialog=$("#ovAccount");
function setAccountMenu(open){
  accountMenu.classList.toggle("open",open);
  if(account)accountButton.setAttribute("aria-expanded",String(open))
}
function showAccount(){
  const registering=accountMode==="register";
  const settings=accountMode==="settings";
  accountButton.textContent=account?.username||"Войти";
  accountButton.title=account?.username||"";
  if(account){
    accountButton.setAttribute("aria-controls","accountActions");
    setAccountMenu(accountMenu.classList.contains("open"))
  }else{
    setAccountMenu(false);
    accountButton.removeAttribute("aria-controls");
    accountButton.removeAttribute("aria-expanded")
  }
  $("#accountTitle").textContent=account?(settings?"Настройки аккаунта":"Профиль"):registering?"Регистрация":"Вход";
  $("#accountForm").hidden=!!account||registering;$("#registerForm").hidden=!!account||!registering;
  $("#accountProfile").hidden=!account||settings;
  $("#pluginsForm").hidden=!account||!settings;
  $("#accountName").textContent=account?.username||"";
  $("#accountEmail").textContent=account?.email||"Не указана";
  $("#pluginsForm").querySelectorAll("[name=plugin]").forEach(input=>{
    input.checked=account?.languagePlugins.includes(input.value)||false
  })
}
function switchAccountMode(mode){
  if(accountPending)return;
  accountMode=mode;
  $("#accountStatus").textContent="";
  for(const field of ["accountPassword","registerPassword","registerConfirmation"])$("#"+field).value="";
  $("#registerConfirmation").removeAttribute("aria-invalid");
  showAccount();
  $(account?"#accountTitle":mode==="register"?"#registerUsername":"#accountUsername").focus()
}
function openAccountDialog(mode){
  if(accountPending)return;
  setAccountMenu(false);
  accountDialog.classList.add("open");
  switchAccountMode(mode)
}
function closeAccountDialog(){
  accountDialog.classList.remove("open");
  for(const input of accountDialog.querySelectorAll('input[type="password"]'))input.value="";
  accountButton.focus()
}
function resetWorkspace(){
  wf={id:"",name:"Проверка секретов",nodes:[],edges:[]};init();
  $("#wfName").value=wf.name;
  sourceId=null;sourceName="";sel=null;
  $("#srcTag").textContent="источник не выбран";$("#srcTag").classList.remove("ok");
  focusCanvas();clearReport();if(tab==="my")left()
}
async function restoreAccount(){
  const origin=API,token=ss.get(accountTokenKey());
  if(!token){account=null;showAccount();return}
  try{const restored=await api("/accounts/me");
    if(origin===API&&token===ss.get(accountTokenKey())){account=restored;showAccount();refreshLibrary()}}
  catch(e){
    if(origin===API&&token===ss.get(accountTokenKey())){
      if(e.code==="invalid_session")ss.set(accountTokenKey(),null);
      account=null;showAccount();
      if(e.code==="invalid_session")refreshLibrary()
    }
  }
}
accountButton.onclick=()=>{
  if(account){
    if(!accountPending)setAccountMenu(!accountMenu.classList.contains("open"));
    return
  }
  if(running||sourceLoading)return toast("Дождитесь завершения текущей операции");
  openAccountDialog("login")
};
$("#openProfile").onclick=()=>openAccountDialog("profile");
$("#openAccountSettings").onclick=()=>openAccountDialog("settings");
accountMenu.addEventListener("focusout",event=>{
  if(event.relatedTarget&&!accountMenu.contains(event.relatedTarget))setAccountMenu(false)
});
document.addEventListener("pointerdown",event=>{
  if(!accountMenu.contains(event.target))setAccountMenu(false)
});
accountDialog.querySelectorAll("[data-close]").forEach(button=>button.onclick=closeAccountDialog);
accountDialog.addEventListener("pointerdown",event=>{
  if(event.target===accountDialog)closeAccountDialog()
});
document.addEventListener("keydown",event=>{
  if(event.key!=="Escape")return;
  if(accountDialog.classList.contains("open"))closeAccountDialog();
  else if(accountMenu.classList.contains("open")){setAccountMenu(false);accountButton.focus()}
});
$("#showRegistration").onclick=()=>switchAccountMode("register");
$("#showLogin").onclick=()=>switchAccountMode("login");
$("#registerConfirmation").oninput=event=>event.currentTarget.removeAttribute("aria-invalid");
async function submitCredentials(event,mode){
  event.preventDefault();
  if(accountPending)return;
  const form=event.currentTarget,button=form.querySelector('[type="submit"]'),status=$("#accountStatus"),origin=API;
  const credentials=Object.fromEntries(new FormData(form));
  credentials.username=credentials.username.trim();
  if(mode==="register"&&credentials.password!==credentials.confirmPassword){
    const confirmation=$("#registerConfirmation");
    confirmation.setAttribute("aria-invalid","true");confirmation.focus();
    status.textContent=ACCOUNT_ERRORS.password_mismatch;return
  }
  form.querySelectorAll('input[type="password"]').forEach(field=>field.value="");
  accountPending=true;button.disabled=true;status.textContent="";
  try{
    const session=await api("/accounts/"+mode,{method:"POST",headers:JH,body:JSON.stringify(credentials)});
    if(API!==origin)return;
    form.reset();
    ss.set(accountTokenKey(),session.token);account=session.account;accountMode="profile";resetWorkspace();showAccount();
    if(accountDialog.classList.contains("open"))$("#accountTitle").focus();
    status.textContent=mode==="register"?"Аккаунт создан.":"Вход выполнен.";
    refreshLibrary()
  }catch(error){status.textContent=error.message}
  finally{accountPending=false;button.disabled=false}
}
$("#accountForm").onsubmit=event=>submitCredentials(event,"login");
$("#registerForm").onsubmit=event=>submitCredentials(event,"register");
$("#pluginsForm").onsubmit=async event=>{
  event.preventDefault();
  if(accountPending||!account)return;
  const status=$("#accountStatus"),button=event.currentTarget.querySelector('[type="submit"]'),origin=API,token=ss.get(accountTokenKey());
  const languagePlugins=[...event.currentTarget.querySelectorAll("[name=plugin]:checked")].map(input=>input.value);
  accountPending=true;button.disabled=true;
  try{
    const updated=await api("/accounts/plugins",{method:"PUT",headers:JH,body:JSON.stringify({languagePlugins})});
    if(API!==origin||ss.get(accountTokenKey())!==token)return;
    account=updated;
    if(wf.languagePlugins)wf.languagePlugins=account.languagePlugins;
    showAccount();inspector();status.textContent="Плагины сохранены."
  }catch(error){status.textContent=error.message}
  finally{button.disabled=false;accountPending=false}
};
$("#logoutBtn").onclick=async()=>{
  if(accountPending||!account)return;
  setAccountMenu(false);
  accountButton.focus();
  if(running||sourceLoading)return toast("Дождитесь завершения текущей операции");
  const key=accountTokenKey(),token=ss.get(key);
  accountPending=true;
  try{await api("/accounts/logout",{method:"POST"})}
  catch(error){if(error.code!=="invalid_session")return fail(error)}
  finally{accountPending=false}
  if(ss.get(key)===token)ss.set(key,null);
  if(key!==accountTokenKey())return;
  account=null;
  accountMode="login";resetWorkspace();showAccount();
  refreshLibrary()
};
// Опубликованные шаблоны целых сценариев.
const LIBRARY_PAGE_SIZE=24;
let libraryQuery="",libraryOffset=0,libraryRequest=0;
let librarySection="workflows",pluginQuery="",pluginOffset=0,pluginRequest=0;
const libraryOpen=()=>location.hash==="#library";
function refreshLibrary(){
  if(!libraryOpen())return;
  if(librarySection==="plugins")loadPluginLibrary();
  else loadLibrary()
}
function showLibrarySection(section){
  librarySection=section;
  const plugins=section==="plugins";
  $("#libraryWorkflows").hidden=plugins;$("#libraryPlugins").hidden=!plugins;
  for(const [selector,active] of [["#libraryWorkflowsTab",!plugins],["#libraryPluginsTab",plugins]]){
    $(selector).classList.toggle("on",active);$(selector).setAttribute("aria-pressed",String(active))
  }
  libraryRequest++;pluginRequest++;
  if(!plugins)$("#pluginCards").replaceChildren();
  refreshLibrary()
}
$("#libraryWorkflowsTab").onclick=()=>showLibrarySection("workflows");
$("#libraryPluginsTab").onclick=()=>showLibrarySection("plugins");
function showLibraryRoute(){
  const open=libraryOpen();
  $(".app").classList.toggle("library-open",open);
  $("#workflowLibrary").hidden=!open;
  $("#libBtn").setAttribute("aria-pressed",String(open));
  if(open)refreshLibrary();
  else{libraryRequest++;pluginRequest++;$("#pluginCards").replaceChildren()}
}
function returnToEditor(){
  location.hash="";
  showLibraryRoute()
}
$("#libBtn").onclick=()=>{location.hash="library"};
$("#libraryBack").onclick=returnToEditor;
addEventListener("hashchange",showLibraryRoute);

async function loadLibrary(offset=0){
  const request=++libraryRequest,list=$("#libraryCards"),status=$("#libraryStatus"),more=$("#libraryMore");
  if(offset===0){list.replaceChildren();more.hidden=true}
  more.disabled=true;status.textContent="Загружаем шаблоны…";
  const params=new URLSearchParams({q:libraryQuery,limit:LIBRARY_PAGE_SIZE+1,offset});
  try{
    const rows=await api("/workflow-templates?"+params);
    if(request!==libraryRequest)return;
    for(const template of rows.slice(0,LIBRARY_PAGE_SIZE))list.append(templateCard(template));
    libraryOffset=offset+Math.min(LIBRARY_PAGE_SIZE,rows.length);
    status.textContent=offset===0&&!rows.length?(libraryQuery?"По этому запросу шаблонов нет.":"Шаблонов пока нет."):"";
    more.hidden=rows.length<=LIBRARY_PAGE_SIZE
  }catch(error){if(request===libraryRequest)status.textContent=error.message}
  finally{if(request===libraryRequest)more.disabled=false}
}
function searchLibrary(query){
  libraryQuery=query.trim();$("#librarySearch").value=libraryQuery;
  loadLibrary()
}
$("#librarySearchForm").onsubmit=event=>{event.preventDefault();searchLibrary($("#librarySearch").value)};
$("#libraryMore").onclick=()=>loadLibrary(libraryOffset);

async function loadPluginLibrary(offset=0){
  const request=++pluginRequest,list=$("#pluginCards"),status=$("#pluginStatus"),more=$("#pluginMore");
  if(offset===0){list.replaceChildren();more.hidden=true}
  more.disabled=true;status.textContent="Загружаем плагины…";
  try{
    const params=new URLSearchParams({q:pluginQuery,limit:LIBRARY_PAGE_SIZE+1,offset});
    const plugins=await api("/plugins?"+params);
    if(request!==pluginRequest)return;
    for(const plugin of plugins.slice(0,LIBRARY_PAGE_SIZE))list.append(pluginCard(plugin));
    pluginOffset=offset+Math.min(LIBRARY_PAGE_SIZE,plugins.length);
    status.textContent=offset===0&&!plugins.length?(pluginQuery?"По этому запросу плагинов нет.":"Плагинов пока нет."):"";
    more.hidden=plugins.length<=LIBRARY_PAGE_SIZE
  }catch(error){if(request===pluginRequest)status.textContent=error.message}
  finally{if(request===pluginRequest)more.disabled=false}
}
$("#pluginSearchForm").onsubmit=event=>{
  event.preventDefault();pluginQuery=$("#pluginSearch").value.trim();loadPluginLibrary()
};
$("#pluginMore").onclick=()=>loadPluginLibrary(pluginOffset);
$("#newPlugin").onclick=()=>openPluginEditor();

function pluginCard(plugin){
  const card=document.createElement("article");card.className="library-card";
  const action=T[plugin.config.scanner]?.n||"Передача находок";
  const language=PLUGIN_NAMES[plugin.config.language];
  const access=plugin.visibility==="public"?"Публичный":"Приватный";
  card.innerHTML=`<h3>${esc(plugin.config.title)}</h3><p class="note">${esc(plugin.author)} · ${access}</p>
    <p>${esc(action)}${language?" · "+esc(language):""}</p>
    <p class="library-description">${esc(plugin.description)}</p>
    <div class="library-actions"><button class="btn pri" data-plugin-add>Добавить на холст</button>
      ${plugin.owned?`<button class="btn" data-plugin-edit>Изменить</button><button class="btn" data-plugin-remove>Удалить</button>`:""}</div>`;
  const button=card.querySelector("[data-plugin-add]");
  button.onclick=()=>addPluginNode(plugin.id,button);
  card.querySelector("[data-plugin-edit]")?.addEventListener("click",()=>openPluginEditor({plugin}));
  card.querySelector("[data-plugin-remove]")?.addEventListener("click",async event=>{
    if(!confirm("Удалить плагин из библиотеки? Добавленные в сценарии ноды сохранятся."))return;
    const remove=event.currentTarget;remove.disabled=true;
    try{await api("/plugins/"+encodeURIComponent(plugin.id)+"/remove",{method:"POST"});refreshLibrary()}
    catch(error){fail(error)}
    finally{remove.disabled=false}
  });
  return card
}
async function addPluginNode(id,button){
  if(running)return toast("Дождитесь завершения проверки");
  const activeWorkflow=wf,viewer=account?.id,origin=API;
  button.disabled=true;
  try{
    const plugin=await api("/plugins/"+encodeURIComponent(id));
    if(!libraryOpen()||librarySection!=="plugins"||running||wf!==activeWorkflow||viewer!==account?.id||origin!==API)return;
    if(plugin.visibility==="private"&&(!plugin.owned||!viewer||wf.id&&!Array.isArray(wf.languagePlugins))){
      toast("Откройте личный сценарий, чтобы добавить приватный плагин.");return
    }
    const config={...plugin.config};
    if(plugin.visibility==="private")config.privatePluginOwner=viewer;
    returnToEditor();addNode("custom",config)
  }catch(error){fail(error);refreshLibrary()}
  finally{button.disabled=false}
}

function templateCard(template){
  const card=document.createElement("article");card.className="library-card";
  card.innerHTML=`<h2>${esc(template.title)}</h2><p class="note">Автор: ${esc(template.author)}</p>
    <p class="library-description">${esc(template.description)}</p>
    ${template.tags.length?`<div class="library-tags">${template.tags.map(tag=>`<button class="btn">${esc(tag)}</button>`).join("")}</div>`:""}
    <div class="library-actions"><button class="btn pri" data-template-copy>Открыть копию</button>
    ${template.workflowId?`<button class="btn" data-template-edit>Изменить</button><button class="btn" data-template-remove>Снять с публикации</button>`:""}</div>`;
  card.querySelectorAll(".library-tags button").forEach((button,index)=>button.onclick=()=>searchLibrary(template.tags[index]));
  const copy=card.querySelector("[data-template-copy]");
  copy.onclick=()=>copyTemplate(template.id,copy);
  card.querySelector("[data-template-edit]")?.addEventListener("click",()=>openPublish(template));
  card.querySelector("[data-template-remove]")?.addEventListener("click",async event=>{
    if(!confirm("Убрать этот шаблон из общей библиотеки?"))return;
    const button=event.currentTarget;button.disabled=true;
    try{await api("/workflow-templates/"+encodeURIComponent(template.id)+"/remove",{method:"POST"});loadLibrary()}
    catch(error){fail(error)}
    finally{button.disabled=false}
  });
  return card
}
async function copyTemplate(id,button){
  if(running)return toast("Дождитесь завершения проверки");
  button.disabled=true;
  try{
    const template=await api("/workflow-templates/"+encodeURIComponent(id));
    if(!libraryOpen()||running)return;
    returnToEditor();
    wf={...template.draft,id:""};$("#wfName").value=wf.name;
    sel=null;focusCanvas();clearReport();
    toast("Копия открыта. Проверьте настройки перед запуском.")
  }catch(error){fail(error)}
  finally{button.disabled=false}
}
async function openPublish(template){
  if(!account){
    $("#libraryStatus").textContent="Войдите, чтобы опубликовать сценарий.";
    $("#accountBtn").click();return
  }
  const owner=account.id,select=$("#publishWorkflow"),status=$("#publishStatus"),button=$("#publishSubmit");
  $("#publishForm").reset();select.replaceChildren();
  $("#ovPublish").classList.add("open");
  button.disabled=true;status.textContent="Загружаем личные сценарии…";
  try{
    const workflows=(await api("/workflows")).filter(workflow=>Array.isArray(workflow.languagePlugins));
    if(owner!==account?.id||!$("#ovPublish").classList.contains("open"))return;
    for(const workflow of workflows)select.add(new Option(workflow.name,workflow.id));
    if(!workflows.length){status.textContent="Сначала сохраните личный сценарий в редакторе.";return}
    const preferred=template?.workflowId||wf.id;
    if(workflows.some(workflow=>workflow.id===preferred))select.value=preferred;
    $("#publishName").value=(template?.title||select.selectedOptions[0].text).slice(0,100);
    $("#publishDescription").value=template?.description||"";
    $("#publishTags").value=template?.tags.join(", ")||"";
    button.disabled=false;status.textContent=""
  }catch(error){status.textContent=error.message}
}
$("#libraryPublish").onclick=()=>openPublish();
$("#publishWorkflow").onchange=event=>{
  $("#publishName").value=event.target.selectedOptions[0].text.slice(0,100);
  $("#publishDescription").value="";$("#publishTags").value=""
};
$("#publishForm").onsubmit=async event=>{
  event.preventDefault();
  const button=$("#publishSubmit"),status=$("#publishStatus");
  if(button.disabled)return;
  const tags=$("#publishTags").value.split(",").map(tag=>tag.trim()).filter(Boolean);
  if(tags.length>8||tags.some(tag=>tag.length>32)){
    status.textContent="Укажите до 8 тегов. Длина каждого — до 32 символов.";return
  }
  button.disabled=true;status.textContent="Публикуем…";
  try{
    await api("/workflow-templates",{method:"PUT",headers:JH,body:JSON.stringify({
      workflowId:$("#publishWorkflow").value,title:$("#publishName").value.trim(),
      description:$("#publishDescription").value.trim(),tags
    })});
    $("#ovPublish").classList.remove("open");searchLibrary("");toast("Шаблон опубликован.")
  }catch(error){status.textContent=error.message}
  finally{button.disabled=false}
};
function modelLabel(id){const i=String(id||"").indexOf(":");return i<0?"":`${id.slice(i+1)} · ${PROVIDERS[id.slice(0,i)]||id.slice(0,i)}`}
function tabModel(){return ss.get("cg_model")}
function activeModel(){return tabModel()||llmSettings?.defaultId||null}
// что отправить бэкенду: без выбора решает сервер, согласие на DeepSeek привязано к конкретной модели
function modelChoice(){const id=tabModel();return id?{modelId:id,allowExternal:ss.get("cg_model_consent")===id}:{}}
function llmReason(o){return{connection_error:"локальный сервер моделей не отвечает. Запущена ли Ollama?",model_missing:`модель не скачана. Выполните ollama pull ${o.model}`,no_api_key:"на бэкенде не задан DEEPSEEK_API_KEY"}[o.reason]||o.reason}
const CHECK_ERRORS={auth_error:"провайдер отклонил ключ API",billing_error:"на аккаунте провайдера недостаточно средств",connection_error:"сервер модели недоступен",model_missing:"такой модели нет на сервере",timeout:"модель не ответила вовремя",rate_limited:"провайдер ограничил частоту запросов",consent_required:"нужно согласие на отправку в DeepSeek",no_api_key:"на бэкенде не задан DEEPSEEK_API_KEY",unknown_model:"бэкенд не предлагает эту модель"};
async function loadLlm(){const s=$("#llmModel"),st=$("#llmStatus");s.disabled=true;st.textContent="Загружаю список моделей…";$("#llmConsent").checked=false;
  try{llmSettings=await api("/settings/llm")}
  catch(e){llmSettings=null;s.innerHTML="";$("#llmConsentRow").hidden=true;st.innerHTML=`<span style="color:var(--bad)">${esc(e.code==="http_error"?"Эта версия бэкенда не поддерживает выбор модели.":e.message)}</span>`;renderAI();return}
  const groups=[["local","Локальная модель: данные остаются на компьютере"],["deepseek","DeepSeek API: внешний сервис"]];
  const cur=activeModel(),known=llmSettings.options.some(o=>o.id===cur);
  s.innerHTML=(cur?"":`<option value="">Не выбрана</option>`)+(cur&&!known?`<option value="${esc(cur)}">${esc(modelLabel(cur))} (нет в списке)</option>`:"")+groups.map(([p,title])=>{const list=llmSettings.options.filter(o=>o.provider===p);
    return list.length?`<optgroup label="${esc(title)}">${list.map(o=>`<option value="${esc(o.id)}" ${o.reason==="no_api_key"?"disabled":""}>${esc(o.model)}${o.available?"":" (недоступна)"}</option>`).join("")}</optgroup>`:""}).join("");
  s.value=cur||"";s.disabled=false;llmStatusNote();renderAI()}
function llmStatusNote(extra=""){const id=$("#llmModel").value,cur=activeModel(),o=llmSettings?.options.find(x=>x.id===id),st=$("#llmStatus");
  $("#llmConsentRow").hidden=!(o?.provider==="deepseek"&&ss.get("cg_model_consent")!==id);
  if(!llmSettings)return;
  if(!o){st.innerHTML=(cur?`Модель ${esc(modelLabel(cur))} бэкенд больше не предлагает.`:"Модель не выбрана: AI-нода и чат работать не будут.")+extra;return}
  const state=!o.available?`<span style="color:var(--bad)">недоступна: ${esc(llmReason(o))}</span>`:o.provider==="local"?"установлена на сервере моделей":"ключ на бэкенде настроен, связь не проверена";
  st.innerHTML=`${o.id===cur?"Сейчас в этой вкладке":"Будет выбрана"}: <b>${esc(o.model)}</b> (${PROVIDERS[o.provider]}), ${state}.${extra}<br>Выбор действует только в этой вкладке и применяется к следующему запуску и вопросу в чате.`}
async function checkLlm(id){const consent=$("#llmConsentRow").hidden?ss.get("cg_model_consent")===id:$("#llmConsent").checked;
  return api("/settings/llm/check",{method:"POST",headers:JH,body:JSON.stringify({modelId:id,allowExternal:consent})})}
function checkText(r){return r.ok?` <span style="color:var(--ok)">Связь проверена: ответ за ${r.seconds} с.</span>`:` <span style="color:var(--bad)">Проверка не прошла: ${esc(CHECK_ERRORS[r.code]||r.message||r.code)}.</span>`}
$("#llmModel").onchange=()=>llmStatusNote();
$("#llmCheck").onclick=async()=>{const id=$("#llmModel").value;if(!id)return;
  if(!$("#llmConsentRow").hidden&&!$("#llmConsent").checked)return toast("Для проверки DeepSeek отметьте согласие на отправку данных");
  $("#llmCheck").disabled=true;$("#llmStatus").textContent="Проверяю связь с моделью…";
  try{llmStatusNote(checkText(await checkLlm(id)))}catch(e){llmStatusNote(` <span style="color:var(--bad)">${esc(CHECK_ERRORS[e.code]||e.message)}</span>`)}
  finally{$("#llmCheck").disabled=false}};
$("#gear").onclick=()=>{$("#apiUrl").value=API;$("#ovSet").classList.add("open");loadLlm()};
$("#setSave").onclick=async()=>{const next=$("#apiUrl").value.trim().replace(/\/+$/,"")||DEFAULT_API;
  if(next!==API){if(running||sourceLoading)return toast("Адрес API можно сменить после завершения операции");webhookRefs=[];webhookListError="Загрузка получателей…";API=next;account=null;resetWorkspace();showAccount();refreshLibrary();ls.set("cg_api",API);ss.set("cg_model",null);ss.set("cg_model_consent",null);const ok=await ping();if(ok){loadLlm();restoreAccount()}
    return toast(ok?"Бэкенд на связи. Проверьте модель для нового адреса.":"Нет связи с бэкендом по адресу "+API)}
  const id=$("#llmModel").value;
  if(llmSettings&&id&&id!==activeModel()){
    const external=!$("#llmConsentRow").hidden;
    if(external&&!$("#llmConsent").checked)return toast("Подтвердите, что находки можно отправлять в DeepSeek");
    $("#setSave").disabled=true;$("#llmStatus").textContent="Проверяю связь с моделью перед сменой…";
    let r;try{r=await checkLlm(id)}catch(e){r={ok:false,code:e.code,message:e.message}}finally{$("#setSave").disabled=false}
    if(!r.ok){$("#llmModel").value=activeModel()||"";llmStatusNote(checkText(r)+" Оставлена прежняя модель.");return}
    ss.set("cg_model",id);if(external)ss.set("cg_model_consent",id);
    renderAI();$("#ovSet").classList.remove("open");
    return toast(`Модель в этой вкладке: ${modelLabel(id)}. Ответ за ${r.seconds} с.`)}
  $("#ovSet").classList.remove("open");toast(await ping()?"Бэкенд на связи":"Нет связи с бэкендом по адресу "+API)};
$("#theme").onclick=()=>{const d=document.documentElement,dark=d.dataset.theme?d.dataset.theme==="dark":matchMedia("(prefers-color-scheme:dark)").matches;d.dataset.theme=dark?"light":"dark"};
$("#aiToggle").onclick=()=>$("#main").classList.remove("ai-open");
// источник
let sourceLoading=false;
const REPO_ERRORS={
  invalid_repository_url:"Укажите HTTPS-ссылку на репозиторий GitHub в формате github.com/владелец/репозиторий.",
  repository_not_allowed:"Репозиторий не входит в список разрешённых учебных проектов.",
  repository_unavailable:"Репозиторий недоступен. Нужен публичный репозиторий с веткой по умолчанию.",
  repository_timeout:"GitHub не успел отдать архив. Попробуйте ещё раз.",
  repository_download_failed:"Не удалось получить ZIP-архив от GitHub."
};
async function loadSource(path,options,label){
  if(running||sourceLoading)return;
  const tag=$("#srcTag"),previous=tag.textContent,origin=API,token=ss.get(accountTokenKey());
  const sameWorkspace=()=>API===origin&&ss.get(accountTokenKey())===token;
  sourceLoading=true;$("#upBtn").disabled=true;$("#repoBtn").disabled=true;
  tag.textContent="Загружаем проект…";
  try{
    const result=await api(path,{method:"POST",...options});
    if(!sameWorkspace())return;
    sourceId=result.sourceId;sourceName=label;tag.textContent="загружен: "+label;
    tag.classList.add("ok");$("#src").classList.remove("need");clearReport()
  }catch(e){if(sameWorkspace()){tag.textContent=previous;toast(REPO_ERRORS[e.code]||e.message)}}
  finally{sourceLoading=false;$("#upBtn").disabled=false;$("#repoBtn").disabled=false}
}
$("#upBtn").onclick=()=>{if(!running&&!sourceLoading)$("#fileIn").click()};
$("#fileIn").onchange=()=>{
  const f=$("#fileIn").files[0];$("#fileIn").value="";
  if(!f)return;
  if(!/\.zip$/i.test(f.name))return toast("Поддерживается только ZIP");
  if(f.size>10*1024*1024)return toast(ERR.upload_too_large);
  const body=new FormData();body.append("file",f);
  loadSource("/sources",{body},f.name)
};
$("#repoBtn").onclick=()=>{
  const url=$("#repoUrl").value.trim();
  if(!url){$("#repoUrl").focus();return toast("Введите ссылку на учебный репозиторий")}
  loadSource("/sources/repository",{headers:JH,body:JSON.stringify({url})},url.replace(/^https:\/\/github\.com\//i,""))
};
$("#repoUrl").onkeydown=e=>{if(e.key==="Enter")$("#repoBtn").click()};
// запуск
const wait=ms=>new Promise(r=>setTimeout(r,ms));
function validate(){const tr=wf.nodes.filter(n=>n.type==="trigger");if(tr.length!==1)return"В сценарии должен быть ровно один запуск";
  const disconnected=wf.nodes.find(n=>n.type!=="trigger"&&n.type!=="source"&&!wf.edges.some(e=>e.target===n.id&&e.targetHandle!=="source"));
  if(disconnected)return `Подключите ноду «${nodeName(disconnected)}» к потоку сценария.`;
  const bad=wf.nodes.filter(n=>!SUPPORTED.has(n.type));if(bad.length)return`Нода «${esc(nodeName(bad[0]))}» пока не выполняется бэкендом. Уберите её, чтобы запустить сценарий.`;
  if(wf.nodes.some(n=>n.type==="notify"&&!n.config.webhookRef))return WEBHOOK_ERRORS.invalid_webhook_ref;
  return null}
$("#runBtn").onclick=async()=>{if(running)return;const err=validate();if(err)return toast(err);
  if(sourceLoading)return toast("Дождитесь загрузки проекта");
  const schedule=wf.nodes.find(n=>n.type==="trigger"&&n.config.mode==="daily")?.config;
  const runSource=sourceId||schedule?.scheduleSourceId;
  if(!runSource){$("#src").classList.add("need");return toast("Загрузите учебный ZIP или репозиторий по ссылке")}
  running=true;$("#runBtn").disabled=true;$("#runBtn").textContent="Идёт запуск…";pick=null;inspector();renderChat();
  try{await save();
    const r=await api(`/workflows/${wf.id}/runs`,{method:"POST",headers:JH,body:JSON.stringify({sourceId:runSource,...modelChoice()})});
    historicalReport=false;report={runId:r.runId,workflowId:wf.id,status:r.status,nodes:wf.nodes.map(n=>({nodeId:n.id,status:"queued"})),findings:[]};openRep();render();renderRep();renderAI();
    for(let i=0;i<150;i++){await wait(800);report=await api("/runs/"+r.runId);report.findings=report.findings||[];render();renderRep();renderAI();if(report.status==="succeeded"||report.status==="failed")break}
    if(report.status==="running"||report.status==="queued")toast("Запуск идёт дольше обычного. Откройте отчёт позже: "+r.runId)}
  catch(e){fail(e)}
  finally{running=false;$("#runBtn").disabled=false;$("#runBtn").textContent="Запустить";render();renderRep();renderAI()}};
// отчёт
function openRep(){$("#rep").classList.remove("min");$("#repToggle").textContent="Свернуть"}
$("#repToggle").onclick=()=>{$("#rep").classList.toggle("min");$("#repToggle").textContent=$("#rep").classList.contains("min")?"Развернуть":"Свернуть"};
const HISTORY_PAGE_SIZE=25;
const historyTime=new Intl.DateTimeFormat("ru",{dateStyle:"short",timeStyle:"short"});
let historyView=null;
function historyIsOpen(view){
  return historyView===view&&$("#ovHistory").classList.contains("open")&&wf.id===view.workflowId
}
async function loadHistory(view){
  const list=$("#historyList"),more=$("#historyMore");
  more.disabled=true;
  try{
    const rows=await api(`/workflows/${encodeURIComponent(view.workflowId)}/runs?limit=${HISTORY_PAGE_SIZE+1}&offset=${view.offset}`);
    if(!historyIsOpen(view))return;
    if(view.offset===0)list.replaceChildren();
    if(!rows.length&&view.offset===0)list.textContent="У этого сценария пока нет запусков.";
    for(const run of rows.slice(0,HISTORY_PAGE_SIZE)){
      if(view.seen.has(run.runId))continue;
      view.seen.add(run.runId);
      const button=document.createElement("button");
      button.className="cat";
      const time=run.createdAt?historyTime.format(new Date(run.createdAt)):"Дата не записана";
      const mode=run.triggerMode==="daily"?" · по расписанию":"";
      button.textContent=`${time} · ${run.runId.slice(0,8)} · ${stLabel(run.status)}${mode} · ${plural(run.findingCount,"находка","находки","находок")}`;
      button.onclick=()=>openHistoryReport(view,run.runId,button);
      list.appendChild(button)
    }
    view.offset+=Math.min(rows.length,HISTORY_PAGE_SIZE);
    more.hidden=rows.length<=HISTORY_PAGE_SIZE
  }catch(e){if(historyIsOpen(view)){if(view.offset===0)list.textContent=e.message;else fail(e)}}
  finally{if(historyIsOpen(view))more.disabled=false}
}
async function openHistoryReport(view,runId,button){
  if(running||view.opening)return;
  view.opening=true;button.disabled=true;
  try{
    const saved=await api("/runs/"+encodeURIComponent(runId));
    if(!historyIsOpen(view)||running)return;
    if(saved.status==="queued"||saved.status==="running")return toast("Запуск ещё выполняется. Откройте отчёт после завершения.");
    report=saved;historicalReport=true;pick=null;sel=null;
    $("#ovHistory").classList.remove("open");openRep();render();renderRep();renderAI()
  }catch(e){if(historyIsOpen(view))fail(e)}
  finally{view.opening=false;button.disabled=false}
}
$("#runHistory").onclick=()=>{
  if(running)return toast("Дождитесь завершения проверки");
  if(!wf.id)return toast("Сначала сохраните сценарий или запустите проверку");
  historyView={workflowId:wf.id,offset:0,opening:false,seen:new Set()};
  $("#historyWorkflow").textContent=wf.name;
  $("#historyList").textContent="Загружаем историю…";
  $("#historyMore").hidden=true;$("#ovHistory").classList.add("open");
  loadHistory(historyView)
};
$("#historyMore").onclick=()=>loadHistory(historyView);
$("#findingsDownload").onclick=async event=>{
  const button=event.currentTarget;
  const runId=report?.runId;
  if(!runId||button.hidden)return;
  button.disabled=true;
  try{
    const findings=await api("/runs/"+encodeURIComponent(runId)+"/findings.json");
    downloadJson("findings.json",JSON.stringify(findings,null,2)+"\n")
  }catch(e){fail(e)}
  finally{button.disabled=false}
};
function nodeNote(n,s){const o=s.output;
  if(n.type==="trigger"&&o?.sourceId)return "<br><small>Проверяется загруженный проект</small>";
  if(n.type==="source"&&o?.sourcePath)return `<br><small>${esc(o.sourcePath)}</small>`;
  if(n.type==="notify"&&o){
    if(o.delivered)return `<br><small>Отправлено (HTTP ${esc(o.statusCode)})</small>`;
    const reason=WEBHOOK_ERRORS[o.errorCode]||(o.statusCode?`Получатель вернул HTTP ${o.statusCode}.`:s.error);
    return `<br><small style="color:var(--bad)">${esc(reason)}</small>`
  }
  if(n.type==="ai"&&o){if(o.aiAvailable===false)return`<br><small style="color:var(--bad)">${esc(LLM_ERRORS[o.errorCode]||"Модель недоступна. Находки сохранены.")}${o.fallback?" Показаны карточки без нейросети.":""}</small>`;
    if(o.aiAvailable)return`<br><small>${aiDoneText(o)}</small>`;
    const st=AI_STAGES.find(x=>x[0]===o.stage);if(st&&s.status==="running")return`<br><small>${st[1]}…</small>`}
  if(s.error)return`<br><small style="color:var(--bad)">${esc(ERR[o?.errorCode]||(s.error==="Node execution failed."?"Нода завершилась с ошибкой":s.error))}</small>`;
  if(!o)return"";if(nodeScanner(n))return`<br><small>находок: ${(o.findings||[]).length}</small>`;if(n.type==="custom")return`<br><small>передано находок: ${+o.passed||0}</small>`;
  if(n.type==="condition")return`<br><small>ветка «${o.matched?"Да":"Нет"}»${o.count==null?"":` · найдено совпадений: ${esc(o.count)}`}</small>`;
  return""}
function findingItem(f) {
  const location = f.line == null ? f.file : f.file + ":" + f.line;
  const advisory = f.cve || f.advisoryId;
  return `<li><button class="finding-item" type="button" data-f="${esc(f.id)}" aria-pressed="${pick === f.id}">
    <b>${esc(location)}</b>${advisory ? ` <small>${esc(advisory)}</small>` : ""}
    <span>${esc(f.message)}</span>
  </button></li>`;
}

function transferList(transfers,input,names,findings){
  if(!transfers.length)return `<p class="note">${input?"Ничего не получено.":"Данные дальше не передавались."}</p>`;
  return `<ul class="transfer-list">${transfers.map(transfer=>{
    const port=transfer.port==="source"?"Источник":transfer.port==="true"?"Выход «Да»":transfer.port==="false"?"Выход «Нет»":
      (input?"Вход":"Выход")+(transfer.port?" "+transfer.port.slice(input?2:3):"");
    const neighbor=names.get(transfer.nodeId)||transfer.nodeId;
    const preview=transfer.findingIds.map(id=>findings.get(id)).filter(Boolean);
    const analyses=transfer.analysisNodeIds.map(id=>names.get(id)||id);
    return `<li><b>${esc(port)}${neighbor?(input?" ← ":" → ")+esc(neighbor):""}</b>
      <p class="note">${transfer.sourcePath?esc(transfer.sourcePath):`${plural(transfer.findingCount,"находка","находки","находок")} · AI-отчётов: ${esc(transfer.analysisCount)}`}</p>
      ${preview.length?`<ul class="finding-items">${preview.map(findingItem).join("")}</ul>`:""}
      ${transfer.findingCount>preview.length?`<p class="note">Показано ${preview.length} из ${esc(transfer.findingCount)}.</p>`:""}
      ${analyses.length?`<p class="note">AI-отчёты от: ${esc(analyses.join(", "))}.</p>`:""}</li>`
  }).join("")}</ul>`
}

function renderFindings(findings, openGroups) {
  if (!findings.length) {
    const message = {
      succeeded: "Находок нет: проверка прошла успешно.",
      failed: "Проверка завершилась с ошибкой. Подробности указаны рядом с нодой."
    }[report.status] || "Идёт проверка…";
    return `<div class="empty">${message}</div>`;
  }

  return Object.entries(REPORT_LEVELS).map(([severity, title]) => {
    const types = new Map();
    let count = 0;
    for (const finding of findings) {
      if (finding.severity !== severity) continue;
      if (!types.has(finding.ruleId)) types.set(finding.ruleId, []);
      types.get(finding.ruleId).push(finding);
      count++;
    }
    if (!count) return "";

    const groups = Array.from(types, ([ruleId, items]) => {
      const group = JSON.stringify([severity, ruleId]);
      const label = Object.hasOwn(RULES, ruleId) ? RULES[ruleId] : ruleId;
      return `<details class="finding-type" data-group="${esc(group)}" ${openGroups.has(group) ? "open" : ""}>
        <summary>${esc(label)} <span class="count">(${items.length})</span></summary>
        <ul class="finding-items">${items.map(findingItem).join("")}</ul>
      </details>`;
    }).join("");
    return `<details class="finding-level ${severity}" data-group="${severity}" ${openGroups.has(severity) ? "open" : ""}>
      <summary><span class="dot" aria-hidden="true"></span>${title} <span class="count">(${count})</span></summary>
      <div class="finding-types">${groups}</div>
    </details>`;
  }).join("");
}

function renderRep(){const b=$("#repBody");$("#findingsDownload").hidden=!report||!["succeeded","failed"].includes(report.status);
  if(!report){delete b.dataset.runId;$("#repTag").textContent="запусков ещё не было";b.innerHTML=`<div class="empty">Загрузите проект и нажмите «Запустить» — здесь появятся статусы нод и находки.</div>`;return}
  $("#repTag").textContent=(historicalReport?"Из истории · ":"")+report.runId.slice(0,8)+" · "+stLabel(report.status)+(report.triggerMode==="daily"?" · по расписанию":"");
  const fs=report.findings||[];
  const findings=new Map(fs.map(f=>[f.id,f]));
  const nodes=new Map(report.nodes.map(result=>[result.nodeId,
    result.type?{type:result.type,config:{title:result.label}}:wf.nodes.find(n=>n.id===result.nodeId)]));
  const names=new Map([...nodes].map(([id,node])=>[id,node?nodeName(node):id]));
  const sameRun=b.dataset.runId===report.runId;
  const openGroups=new Set(sameRun?Array.from(b.querySelectorAll("details[data-group][open]"),e=>e.dataset.group):[]);
  const openTransfers=new Set(sameRun?Array.from(b.querySelectorAll(".node-transfer[open]"),e=>e.dataset.node):[]);
  const scrollTop=sameRun?b.scrollTop:0;
  b.dataset.runId=report.runId;
  b.dataset.issuesFor=sel?.t==="n"?sel.id:"";
  b.innerHTML=nodeIssuesBlock()+`<div><h4>Ноды</h4><div class="nl">${report.nodes.map(s=>{
    const n=nodes.get(s.nodeId);
    const header=`<span>${esc(names.get(s.nodeId))}${n?nodeNote(n,s):""}</span><small>${stLabel(s.status)}</small>`;
    if(!s.inputs||!s.outputs)return `<div>${header}</div>`;
    return `<details class="node-transfer" data-node="${esc(s.nodeId)}" ${openTransfers.has(s.nodeId)?"open":""}>
      <summary>${header}</summary>
      <h4>Получено</h4>${transferList(s.inputs,true,names,findings)}
      <h4>Передано</h4>${transferList(s.outputs,false,names,findings)}
    </details>`
  }).join("")}</div></div>
  <div><h4>Находки (${fs.length})</h4>${renderFindings(fs,openGroups)}</div>`;
  b.scrollTop=scrollTop;
  const findingButtons=b.querySelectorAll(".finding-item");
  findingButtons.forEach(item=>item.onclick=()=>{
    pick=item.dataset.f;
    findingButtons.forEach(button=>button.setAttribute("aria-pressed",String(button.dataset.f===pick)));
    renderAI()
  })}
let chatState = {runId: null, turns: [], pending: false, error: ""};

function renderChat(scroll = false) {
  const ready = !running && report && ["succeeded", "failed"].includes(report.status);
  const runId = ready ? report.runId : null;
  const input = $("#chatIn");
  const button = $("#chatBtn");
  const log = $("#chatLog");
  if (chatState.runId !== runId) {
    chatState = {runId, turns: [], pending: false, error: ""};
    input.value = "";
  }
  input.disabled = button.disabled = !ready || chatState.pending;
  input.placeholder = ready ? "Вопрос по отчёту…" : "Сначала запустите проверку";
  button.textContent = chatState.pending ? "Ждём ответ…" : "Спросить";
  const waited = chatState.pending ? Math.round((Date.now() - chatState.sentAt) / 1000) : 0;
  const pendingNote = !chatState.pending ? "" : `<div class="msg">${waited >= 20
    ? `Модель отвечает дольше обычного (${waited} с). Локальной модели при первом запросе нужно до минуты.`
    : "Вопрос отправлен, модель отвечает…"}</div>`;
  log.innerHTML = chatState.turns.map(turn =>
    `<div class="msg ${turn.role === "user" ? "me" : ""}">${turn.role === "user" ? esc(turn.content) : fmtAnswer(turn.content)}</div>`
  ).join("") + pendingNote + (chatState.error
    ? `<div class="warn">${esc(chatState.error)}<br><button type="button" class="btn" id="chatRetry">Отправить ещё раз</button></div>` : "");
  $("#chatRetry")?.addEventListener("click", () => $("#reportChat").requestSubmit());
  if (scroll) log.parentElement.scrollTop = log.parentElement.scrollHeight;
}

// Ответы модели — обычный текст. Подсвечиваем только `код` и **жирный**, после экранирования.
function fmtAnswer(text) {
  return esc(text).replace(/`([^`\n]+)`/g, "<code>$1</code>").replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>");
}

$("#reportChat").onsubmit = async event => {
  event.preventDefault();
  const input = $("#chatIn");
  const question = input.value.trim();
  const state = chatState;
  if (!question || !state.runId || state.pending || running) return;
  const history = state.turns.slice(-8).map(turn => ({...turn, content: turn.content.slice(0, 2000)}));
  state.turns.push({role: "user", content: question});
  state.pending = true;
  state.sentAt = Date.now();
  state.error = "";
  input.value = "";
  renderChat(true);
  const slowTimer = setTimeout(() => { if (chatState === state && state.pending) renderChat(true) }, 20500);
  try {
    const reply = await api(`/runs/${encodeURIComponent(state.runId)}/chat`, {
      method: "POST", headers: JH, body: JSON.stringify({question, history, ...modelChoice()})
    });
    state.turns.push({role: "assistant", content: reply.answer});
  } catch (error) {
    state.turns.pop();
    state.error = LLM_ERRORS[error.code] || error.message || "Не удалось получить ответ.";
    if (chatState === state) input.value = question;
  } finally {
    clearTimeout(slowTimer);
    state.pending = false;
    if (chatState === state) {
      renderChat(true);
      input.focus();
    }
  }
};

// AI-панель: итог и приоритеты, ниже свёрнутые карточки групп. Пока AI-нода работает, показываем реальные этапы.
const AI_STAGES=[["preparing","Готовим находки"],["waiting","Ждём ответ модели"],["validating","Проверяем рекомендации"],["done","Готово"]];
const aiWaitStart={};
function plural(n,one,few,many){const a=n%10,b=n%100;return`${n} ${a===1&&b!==11?one:a>=2&&a<=4&&(b<12||b>14)?few:many}`}
function aiDoneText(o){return`объяснено ${o.explained} из ${o.total}${o.limit?` · лимит ${o.limit} самых критичных групп`:""}${o.model?` · ${esc(modelLabel(o.model))}`:""}${o.cached?" · из кэша":""}`}
function aiStageBox(s){const o=s.output,idx=AI_STAGES.findIndex(x=>x[0]===o.stage);
  let waited=0;if(o.stage==="waiting"){const k=`${report.runId}:${s.nodeId}:${o.attempt||1}`;aiWaitStart[k]??=Date.now();waited=Math.round((Date.now()-aiWaitStart[k])/1000)}
  const detail={preparing:o.sent==null?"":`в запрос идут ${o.sent} из ${plural(o.total,"находки","находок","находок")}, ${plural(o.groups,"группа","группы","групп")}`,
    waiting:[o.attempt>1?"повторный запрос: прошлый ответ не прошёл проверку":"",waited>=3?`${waited} с`:""].filter(Boolean).join(", ")};
  const items=AI_STAGES.slice(0,idx+1).map(([id,label],i)=>`<li class="${i<idx?"done":"now"}">${label}${detail[id]?` <small>· ${esc(detail[id])}</small>`:""}</li>`).join("");
  const slow=waited>=30?`<div class="warn" style="margin-top:8px">Модель отвечает дольше обычного. Локальная модель при первом запросе загружается в память, это может занять до минуты.</div>`:"";
  return`<div class="rec ai-stage"><b>AI обрабатывает отчёт</b><ol>${items}</ol>${slow}</div>`}
function aiCard(g,open){const fs=g.findingIds.map(id=>(report.findings||[]).find(f=>f.id===id)).filter(Boolean);
  const picked=fs.some(f=>f.id===pick);
  return`<details class="ai-card ${picked?"pick":""}" data-g="${esc(g.id)}" ${open.has(g.id)||picked?"open":""}>
    <summary><span class="sev ${esc(g.severity)}" aria-hidden="true"></span><b>${esc(g.title)}</b>${fs.length>1?`<span class="count">· ${plural(fs.length,"находка","находки","находок")}</span>`:""}${g.source==="template"&&report?.aiAnalysis?.source!=="template"?`<span class="count" title="Модель не разобрала эту группу, текст собран по правилу анализатора">· без нейросети</span>`:""}<span class="act">${esc(g.action)}</span></summary>
    <div class="more"><p>${esc(g.explanation)}</p><p><small>${esc(g.rationale)}</small></p><ul>${fs.map(findingItem).join("")}</ul></div></details>`}
function renderAI(){const b=$("#aiBody"),a=report?.aiAnalysis;
  const aiRes=(report?.nodes||[]).filter(s=>wf.nodes.find(n=>n.id===s.nodeId)?.type==="ai");
  const active=aiRes.find(s=>s.status==="running"&&s.output?.stage);
  const failed=aiRes.map(s=>s.output).find(o=>o?.aiAvailable===false);
  const done=aiRes.map(s=>s.output).filter(o=>o?.aiAvailable);
  const current=modelLabel(activeModel());
  const template=a?.source==="template";
  $("#llmTag").textContent=active?"AI работает…":template?"Без нейросети":a?"AI-анализ готов":failed?"LLM недоступна":current;
  $("#llmTag").title=current?`Модель для следующего запроса: ${current}. Сменить можно в настройках.`:"";
  renderChat();
  const sameRun=b.dataset.runId===report?.runId;
  const open=new Set(sameRun?Array.from(b.querySelectorAll("details[open]"),d=>d.dataset.g):[]);
  b.dataset.runId=report?.runId||"";
  const stage=active?aiStageBox(active):"";
  if(!a){b.innerHTML=stage||`<div class="empty">${failed?esc(LLM_ERRORS[failed.errorCode]||"Модель недоступна. Находки сохранены."):"Добавьте ноду «AI-рекомендации» после анализаторов, чтобы получить советы автоматически, или задайте вопрос по готовому отчёту."}</div>`;return}
  if(!a.groups?.length){// отчёт старой версии бэкенда: рекомендации по одной находке
    b.innerHTML=stage+`<div class="rec"><b>Итог</b>${esc(a.summary)}</div>`+a.recommendations.map(r=>{const f=(report.findings||[]).find(x=>x.id===r.findingId);return f?`<div class="rec ${pick===f.id?"pick":""}"><b>${esc(f.file)}${f.line?":"+f.line:""}</b>${esc(r.explanation)}<br><br><i>Что сделать:</i> ${esc(r.remediation)}</div>`:""}).join("");return}
  const byId=Object.fromEntries(a.groups.map(g=>[g.id,g]));
  const prio=(a.priorities||[]).filter(p=>byId[p.groupId]);
  const why=template&&failed?(LLM_ERRORS[failed.errorCode]||"Модель недоступна."):"";
  const note=template?`<div class="warn" style="margin-bottom:8px">${esc(why)} Карточки собраны по типам находок без нейросети: проверьте подробности в отчёте.</div>`:"";
  b.innerHTML=stage+note+`<div class="rec ai-top"><b>Итог</b>${esc(a.summary)}
    ${prio.length?`<ol>${prio.map(p=>`<li><span class="sev ${esc(byId[p.groupId].severity)}" aria-hidden="true"></span>${esc(p.action)} <small>· ${esc(byId[p.groupId].title)}</small></li>`).join("")}</ol>`:""}
    ${done.length?`<p style="margin:6px 0 0"><small>${done.map(aiDoneText).join("; ")}</small></p>`:""}</div>`
    +a.groups.map(g=>aiCard(g,open)).join("");
  b.querySelectorAll(".finding-item").forEach(item=>item.onclick=()=>{pick=item.dataset.f;renderRep();renderAI()})}
$("#wfName").oninput=e=>wf.name=e.target.value;
init();left();render();renderRep();renderAI();restoreAccount();showLibraryRoute();ping().then(ok=>ok&&loadLlm());

// Панели и библиотека
(()=>{
  const main=$("#main");
  if(innerWidth<=900)main.classList.remove("ai-open");
  const lib=()=>setNodeCatalog(!main.classList.contains("lib-open"));
  $("#nodeCatalogBtn").onclick=lib;$("#libTab").onclick=lib;
  $("#chatFab").onclick=()=>{main.classList.add("ai-open");$("#chatIn").focus()};
  document.querySelector('[data-a="zip"]').addEventListener("click",()=>{if(!running)$("#fileIn").click()});
  ["ovSet","ovJson","ovHistory","ovGenerate","ovPublish"].forEach(id=>{const o=$("#"+id);o.addEventListener("pointerdown",e=>{if(e.target===o)o.classList.remove("open")})});
  addEventListener("keydown",e=>{if(e.key==="Escape")document.querySelectorAll(".ov.open").forEach(o=>o.classList.remove("open"))});
})();
