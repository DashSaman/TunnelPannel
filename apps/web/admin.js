/* Tehran Network owner console. Credentials stay in form memory only. */
(()=>{'use strict';
let active='users',generation=0;
const labels={max_route_mbps:['سقف سرعت هر مسیر · Mbps','Route rate ceiling · Mbps'],max_route_bytes:['سقف مصرف هر مسیر · بایت','Route payload ceiling · bytes'],max_route_connections:['اتصال هم‌زمان هر مسیر','Connections per route'],max_nodes:['سرور','Servers'],max_tunnels_per_route:['تونل در هر مسیر','Members per route'],max_campaign_methods:['روش در هر تست','Methods per test'],max_active_campaigns:['تست هم‌زمان','Concurrent tests'],max_active_routes:['مسیر فعال','Active routes'],max_daily_candidate_units:['واحد تست روزانه','Daily test units']};
const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e};
const add=(parent,...children)=>{parent.append(...children);return parent};
function input(form,name,title,value='',type='text',required=true){const label=el('label'),field=el('input');field.name=name;field.type=type;field.value=value??'';field.required=required;if(type==='password'){field.autocomplete='new-password';field.minLength=12;field.maxLength=256}else if(type==='number'){field.min=1;field.step=1}field.dir='auto';add(label,el('span',title),field);form.append(label);return field}
function select(form,name,title,options,value){const label=el('label'),field=el('select');field.name=name;for(const [v,text]of options)field.add(new Option(text,v));if(value!==undefined)field.value=value;add(label,el('span',title),field);form.append(label);return field}
function check(form,name,title,value){const label=el('label',undefined,'check'),field=el('input');field.name=name;field.type='checkbox';field.checked=!!value;add(label,field,el('span',title));form.append(label);return field}
function form(parent,title){const box=el('section',undefined,'card'),f=el('form',undefined,'admin-form');add(box,el('h3',title),f);parent.append(box);return f}
function limitsForm(f,values,t){const fields={};for(const [key,names]of Object.entries(labels)){fields[key]=input(f,key,t(...names),values[key],'number');fields[key].max=({max_daily_candidate_units:1000000,max_route_mbps:100000,max_route_bytes:1e16,max_route_connections:10000})[key]||1000}return()=>Object.fromEntries(Object.entries(fields).map(([key,field])=>[key,Number(field.value)]))}
window.TPAdmin={async render({api,t,notify,refresh,user,sensitive}){
 const serial=++generation,authVersion=TPAuth.version;
 const [workspaces,accounts,plans,payments,requests]=await Promise.all([api('/api/billing/workspaces'),api('/api/accounts'),api('/api/billing/owner/plans'),api('/api/billing/owner/payments'),api('/api/billing/owner/requests')]);
 if(serial!==generation||authVersion!==TPAuth.version)return;
 const root=document.getElementById('commercial-admin');root.replaceChildren();
 const toolbar=el('div',undefined,'admin-tabs'),panel=el('div',undefined,'admin-panel');
 const summary=el('div',undefined,'admin-stats');
 for(const [value,title]of [[accounts.length,t('حساب','Accounts')],[workspaces.length,t('فضای مشتری','Workspaces')],[payments.length,t('رسید ثبت‌شده','Recorded receipts')]])add(summary,add(el('div',undefined,'card'),el('strong',String(value)),el('span',title)));
 add(root,summary,toolbar,panel);
 const run=async(button,task)=>{button.disabled=true;try{await task()}catch(e){notify(e.message,true)}finally{if(button.isConnected)button.disabled=false}};
 const action=(label,task,cls='')=>{const b=el('button',label,cls);b.type='button';b.onclick=()=>run(b,task);return b};
 const submit=(f,label,task)=>{const b=el('button',label,'primary');b.type='submit';f.append(b);f.onsubmit=e=>{e.preventDefault();run(b,async()=>{try{await task()}finally{f.querySelectorAll('input[type=password]').forEach(x=>x.value='')}})}};
 const money=p=>p.price_minor===null?t('قیمت تعیین نشده','Price not configured'):Number(p.price_minor).toLocaleString()+' '+p.currency;
 function switchTo(tab){active=tab;panel.replaceChildren();for(const b of toolbar.children)b.setAttribute('aria-selected',String(b.dataset.tab===tab));({users:usersView,plans:plansView,payments:paymentsView,workspaces:workspaceView,traffic:trafficView,migration:migrationView})[tab]()}
 for(const [id,title]of [['users',t('کاربران','Users')],['workspaces',t('دسترسی و سهمیه','Access & quotas')],['traffic',t('مصرف مشترک ماهانه','Shared monthly usage')],['migration',t('مهاجرت تونل‌های قدیمی','Migrate existing tunnels')],['plans',t('پلن‌ها و قیمت','Plans & prices')],['payments',t('پرداخت‌های دستی','Manual payments')]]){const b=action(title,async()=>switchTo(id));b.dataset.tab=id;b.setAttribute('role','tab');toolbar.append(b)}
 toolbar.setAttribute('role','tablist');toolbar.setAttribute('aria-label',t('مدیریت سامانه','Administration'));
 function usersView(){
  const f=form(panel,t('ساخت کاربر جدید','Create a customer'));
  const scope=select(f,'scope',t('نوع حساب','Account type'),[['customer',t('مشتری با فضای مستقل','Customer with an isolated workspace')],['system',t('مدیر سامانه؛ دسترسی به همه مشتری‌ها','System owner; access to all customers')]],'customer');
  const name=input(f,'display_name',t('نام مشتری','Customer name'));
  const username=input(f,'username',t('نام کاربری','Username'));username.pattern='[A-Za-z0-9][A-Za-z0-9_.-]{2,63}';username.autocomplete='off';
  const password=input(f,'password',t('رمز ورود؛ حداقل ۱۲ نویسه','Password; at least 12 characters'),'','password');
  const email=input(f,'email',t('ایمیل اختیاری','Email (optional)'),'','email',false);
  submit(f,t('ساخت حساب مشتری','Create customer account'),async()=>{
   if(accounts.some(a=>a.username?.toLowerCase()===username.value.toLowerCase()))throw Error(t('این نام کاربری قبلاً ثبت شده است.','This username already exists.'));
   let workspaceId=scope.value==='system'?'system':f.dataset.pendingWorkspace;
   if(!workspaceId){const w=await api('/api/workspaces',{name:name.value});workspaceId=w.id;f.dataset.pendingWorkspace=w.id}
   await api('/api/accounts',{workspace_id:workspaceId,username:username.value,password:password.value,display_name:name.value,...(email.value?{email:email.value}:{})});
   notify(t('حساب ساخته شد؛ برای شروع کار، پلن و رسید پرداخت را ثبت کنید.','Account created. Assign access by recording a paid plan receipt.'));await refresh();
  });
  const search=el('input');search.type='search';search.placeholder=t('جستجوی کاربر','Search accounts');search.setAttribute('aria-label',search.placeholder);panel.append(search);
  const list=el('div',undefined,'admin-list');panel.append(list);
  function show(){list.replaceChildren();for(const a of accounts.filter(a=>[a.username,a.email,a.display_name].join(' ').toLowerCase().includes(search.value.toLowerCase()))){
   const card=el('article',undefined,'card'),w=workspaces.find(w=>w.id===a.workspace_id);
   add(card,el('h3',a.display_name||a.username||a.email),el('p',(a.username||a.email)+' · '+(a.workspace_id==='system'?t('مدیر سامانه','System owner'):w?.name||a.workspace_id)),el('p',(a.enabled?t('فعال','Enabled'):t('غیرفعال','Disabled'))+' · '+a.role));
   card.append(action(t('ویرایش حساب','Edit account'),async()=>editAccount(a,card)));list.append(card)
  }}search.oninput=show;show();
 }
 function editAccount(a,card){
  card.replaceChildren();const f=el('form',undefined,'admin-form');card.append(f);
  const username=input(f,'username',t('نام کاربری','Username'),a.username||'', 'text',false);
  const name=input(f,'display_name',t('نام نمایشی','Display name'),a.display_name||'', 'text',false);
  const email=input(f,'email',t('ایمیل','Email'),a.email,'email');
  const role=select(f,'role',t('سطح دسترسی','Role'),[['SUPER_ADMIN',t('مدیر فضای مشتری','Workspace administrator')],['OPERATOR',t('اپراتور','Operator')],['VIEWER',t('فقط مشاهده','Read only')]],a.role);
  const enabled=check(f,'enabled',t('ورود فعال باشد','Allow sign in'),a.enabled);
  const password=input(f,'password',t('رمز جدید؛ خالی یعنی حفظ رمز','New password; blank keeps current'),'','password',false);
  add(f,el('p',t('ذخیرهٔ ویرایش، نشست‌های این حساب را می‌بندد.','Saving revokes this account’s current sessions.'),'muted'));
  submit(f,t('ذخیره حساب','Save account'),async()=>{await api('/api/accounts/'+a.id,{display_name:name.value,email:email.value,role:role.value,enabled:enabled.checked,...(username.value?{username:username.value}:{}),...(password.value?{password:password.value}:{})},'PATCH');notify(t('حساب ویرایش شد.','Account updated.'));if(a.id===user.account_id){await TPAuth.logout();location.href=TPAuth.url('/portal')}else await refresh()});
 }
 function workspaceView(){for(const w of workspaces){
  const f=form(panel,w.name),s=w.subscription;
  const name=input(f,'name',t('نام مشتری','Customer name'),w.name);
  const enabled=check(f,'enabled',t('دسترسی فضای مشتری فعال باشد','Enable customer workspace'),w.enabled);
  const stop=check(f,'stop_on_expiry',t('پس از انقضا، فقط تونل‌های همین مشتری متوقف شوند؛ اختیاری','Optionally stop only this customer’s owned tunnels after expiry'),s.stop_on_expiry);stop.disabled=!s.plan;
  add(f,el('p',(s.plan||t('بدون پلن','No plan'))+' · '+s.state+' · '+(s.paid_through?new Date(s.paid_through*1000).toLocaleDateString():t('نیازمند فعال‌سازی','Activation required')),'muted'));
  if(s.mode==='internal_test')add(f,el('p',t('آزمایش داخلی؛ بدون دریافت وجه و بدون تمدید خودکار','Internal test; no payment collected and no automatic renewal'),'badge'));
  const readLimits=limitsForm(f,w.limits,t);
  add(f,el('p',t('سهمیهٔ مؤثر، کمترین مقدارِ محدودیت مشتری و پلن فعال است. این سهمیه بین حساب‌های همان فضا مشترک است.','Effective quota is the lower of workspace and subscribed-plan limits, shared by accounts in this workspace.'),'muted'));
  submit(f,t('ذخیره محدودیت‌ها','Save quotas'),async()=>{await api('/api/workspaces/'+w.id,{name:name.value,enabled:enabled.checked,limits:readLimits()},'PATCH');if(s.plan&&stop.checked!==s.stop_on_expiry)await api('/api/billing/workspaces/'+w.id+'/policy',{stop_on_expiry:stop.checked});notify(t('محدودیت‌ها ذخیره شد.','Quotas saved.'));await refresh()});
  const advanced=el('details');advanced.append(el('summary',t('دسترسی API و یکپارچه‌سازی','API access & integration')));advanced.append(action(t('چرخش کلید API همین مشتری','Rotate this customer’s API key'),async()=>sensitive(await api('/api/workspaces/'+w.id+'/rotate-key',{}))));f.parentElement.append(advanced);
  if(s.state==='pending_payment'&&!s.plan){
   const trial=el('details');trial.append(el('summary',t('دسترسی آزمایشی داخلی؛ بدون دریافت وجه','Internal test access; no payment collected')));f.parentElement.append(trial);
   const grant=form(trial,t('تست یک‌باره برای مشتری جدید','One-time test for a new customer'));
   add(grant,el('p',t('فقط یک بار، حداکثر هفت روز، با محدودیت‌های Starter. رسید مالی ثبت نمی‌شود؛ پس از انقضا فقط مسیرهای همین مشتری متوقف می‌شوند. سهمیهٔ حجم را جداگانه تعیین کنید.','Once only, up to seven days with Starter limits. No payment receipt is recorded. Only this customer’s routes stop after expiry; grant volume separately.'),'muted'));
   const days=input(grant,'days',t('مهلت آزمایش؛ روز','Test duration; days'),1,'number');days.min=1;days.max=7;
   const reason=input(grant,'reason',t('دلیل ثبت دسترسی آزمایشی','Reason for test access'),'','text');reason.minLength=8;reason.maxLength=200;
   const requestId=crypto.randomUUID().replaceAll('-','');
   submit(grant,t('فعال‌سازی تست بدون پرداخت','Activate test without payment'),async()=>{await api('/api/billing/owner/workspaces/'+w.id+'/test-access',{request_id:requestId,days:Number(days.value),reason:reason.value});notify(t('دسترسی آزمایشی ثبت شد؛ وجهی دریافت نشده است.','Test access granted; no money collected.'));await refresh()});
  }
 }}
 function trafficView(){
  const chooser=form(panel,t('سهمیه مشترک تمام مسیرهای مشتری','One allowance for every customer route'));
  const target=select(chooser,'workspace',t('مشتری','Customer'),workspaces.map(w=>[w.id,w.name]));
  const area=el('div');panel.append(area);let selectedGeneration=0;
  const bytes=n=>n===null?t('بدون سقف','Unlimited'):Number(n).toLocaleString()+' '+t('بایت','bytes');
  async function load(){const selected=target.value,request=++selectedGeneration;if(!selected)return;
   const state=await api('/api/billing/owner/workspaces/'+selected+'/traffic');if(request!==selectedGeneration||!area.isConnected)return;
   area.replaceChildren();const p=state.period,card=el('section',undefined,'card');
   add(card,el('h3',t('مصرف تجمیعی ارسال و دریافت','Combined upload and download usage')),
    el('p',t('مصرف ثبت‌شده: ','Reported usage: ')+bytes(state.used_bytes)),
    el('p',t('اعتبار رزروشده روی مسیرها: ','Credit held by routes: ')+bytes(state.held_bytes)),
    el('p',t('قابل تخصیص: ','Available to allocate: ')+bytes(state.available_bytes)),
    el('p',t('مسیرهای مجهز به حسابداری: ','Accounting-enabled routes: ')+state.coverage.managed_routes));
   if(p&&!p.unlimited){const ceiling=Number(p.quota_bytes)/1073741824;add(card,el('p',t('سقف کل دوره: ','Total period ceiling: ')+ceiling.toLocaleString(undefined,{maximumFractionDigits:3})+' GiB','allowance-ceiling'));const meter=el('progress');meter.max=p.quota_bytes;meter.value=state.used_bytes;meter.setAttribute('aria-label',t('مصرف سهمیه مشترک','Shared allowance usage'));card.append(meter)}
   if(p)add(card,el('p',p.unlimited?t('ثبت مصرف بدون سقف تا تخصیص مدیر','Recording without a ceiling until the administrator assigns one'):(p.expired?t('دوره منقضی شده','Period expired'):t('دوره فعال','Active period'))+' · '+new Date(p.starts_at*1000).toLocaleString()+(p.ends_at?' → '+new Date(p.ends_at*1000).toLocaleString():'')));
   if(state.coverage.unmetered_routes.length)add(card,el('p',t('مسیر فعال قدیمی وجود دارد. برای حفظ تونل‌ها، سهمیه مشترک فعال نمی‌شود؛ مهاجرت باید جداگانه و صریح توسط مدیر انجام شود.','Active unmetered routes exist. Shared accounting is refused to preserve them; migration requires an explicit separate owner action.'),'bad'));
   add(card,el('p',t('اعتبار در اختیار مسیر، مصرف قطعی نیست. اعتبار استفاده‌نشده پس از بیکارشدن مسیر برمی‌گردد؛ اعتبار سرور قطع‌شده تا تأیید ایمن آزاد نمی‌شود. این سهمیه بین حساب‌های همین مشتری و همه سرورهای مسیر مشترک است.','Held credit is not confirmed usage. Idle routes return unused credit; offline credit stays held until safely reconciled. All accounts and route sources in this customer workspace share this pool.'),'muted'));area.append(card);
   const f=form(area,p?t('ویرایش یا تخصیص دوره جدید','Edit allowance or allocate a new period'):t('تخصیص سهمیه توسط مدیر','Allocate customer allowance'));
   const initial=p?.quota_bytes||Math.max(10*1073741824,state.used_bytes+state.held_bytes);
   const unit=select(f,'unit',t('واحد حجم','Volume unit'),[['1',t('بایت','Bytes')],['1048576','MiB'],['1073741824','GiB'],['1099511627776','TiB']],initial<1048576?'1':'1073741824');
   const amount=input(f,'quota',t('سقف کل دوره؛ افزایش آن مصرف قبلی را پاک نمی‌کند','Total period ceiling; increasing keeps previous usage'),initial/Number(unit.value),'number');amount.min=0.000001;amount.step='any';amount.max=Number.MAX_SAFE_INTEGER;
   let previousUnit=Number(unit.value);unit.onchange=()=>{amount.value=Number(amount.value)*previousUnit/Number(unit.value);previousUnit=Number(unit.value)};
   const finish=input(f,'ends_at',t('پایان دوره؛ به وقت دستگاه شما','Period end; your device local time'),'','datetime-local');
   const end=new Date((p?.ends_at||Date.now()/1000+30*86400)*1000);finish.value=new Date(end.getTime()-end.getTimezoneOffset()*60000).toISOString().slice(0,16);
   const reset=check(f,'new_period',t('دوره جدید؛ سوابق دوره قبلی حفظ می‌شود و اعتبارهای باز باید بسته باشند','New period; preserve previous history, all held credit must be closed'),false);reset.disabled=!p;
   add(f,el('p',t('پیش‌فرض دوره تازه ۳۰ روز است. تمدید، حجم و دوره جدید فقط با ثبت مدیر انجام می‌شود؛ پرداخت یا پاک‌کردن مصرف خودکار نیست.','A new period defaults to 30 days. The administrator grants volume, extensions and new periods; no automatic charge or usage reset.'),'muted'));
   submit(f,t('ثبت سهمیه مشتری','Save customer allowance'),async()=>{const quota=Math.round(Number(amount.value)*Number(unit.value));if(!Number.isSafeInteger(quota)||quota<1)throw Error(t('حجم معتبر وارد کنید.','Enter a valid byte allowance.'));await api('/api/billing/owner/workspaces/'+selected+'/traffic',{quota_bytes:quota,ends_at:new Date(finish.value).getTime()/1000,expected_revision:p?.revision||0,new_period:reset.checked},'PUT');notify(t('سهمیه مشترک ثبت شد؛ سوابق مصرف حفظ شدند.','Shared allowance saved; usage history preserved.'));await load()});
   if(state.periods.length){const history=el('section',undefined,'card');history.append(el('h3',t('سوابق دوره‌ها','Period history')));for(const old of state.periods)add(history,el('p',new Date(old.starts_at*1000).toLocaleString()+(old.ends_at?' → '+new Date(old.ends_at*1000).toLocaleString():'')+' · '+bytes(old.used_bytes)+' / '+bytes(old.quota_bytes)));area.append(history)}
  }
  target.onchange=()=>run(target,load);chooser.append(action(t('بررسی و تازه‌سازی مصرف','Inspect and refresh usage'),load));run(target,load);
 }
 function migrationView(){
  const chooser=form(panel,t('انتقال مسیرهای ثبت‌شده به حسابداری مشترک','Enroll registered routes in shared accounting'));
  add(chooser,el('p',t('بدون ورود دستی به سرور: تنظیمات و تونل‌های زیرین حفظ می‌شوند؛ فقط دروازه پس از سالم و بیکارشدن جابه‌جا می‌شود. اتصال TCP قبلی ممکن است نیاز به اتصال دوباره داشته باشد.','No manual server login: settings and underlying tunnels are retained. Only the gateway switches after becoming healthy and idle. Existing TCP sessions may need to reconnect.'),'muted'));
  add(chooser,el('p',t('مصرف از مهاجرت بدون سقف تا تخصیص مدیر ثبت می‌شود؛ مصرف نامعلوم قبلی ساخته نمی‌شود. این کار پلن یا پرداخت مشتری را فعال نمی‌کند.','Usage is recorded from migration without a ceiling until an administrator assigns one. Unknown past usage is not invented; customer payment or plan access is not activated.'),'muted'));
  const target=select(chooser,'migration_workspace',t('مشتریِ مسیرهای مهاجرت','Migration customer'),[['system',t('مسیرهای خود مدیر','Owner routes')],...workspaces.map(w=>[w.id,w.name])]);
  const area=el('div',undefined,'admin-list');panel.append(area);let requestGeneration=0;
  const messages={fresh_preflight_required:t('پیش‌بررسی تازه لازم است؛ از کارت مسیر، بررسی و ادامه را بزنید.','A fresh preflight is required; inspect the route again to continue.'),busy:t('یک مهاجرت در حال اجراست؛ پس از پایان دوباره بررسی کنید.','Another migration is running; inspect again after it finishes.'),already_metered:t('این مسیر قبلاً به حسابداری مجهز شده است.','This route is already accounted.'),workspace_disabled:t('فضای مشتری غیرفعال است.','Customer workspace is disabled.'),existing_ceiling:t('این مشتری سقف فعال دارد؛ برای مهاجرت این وضعیت نیاز به بررسی مدیر دارد.','This customer already has a ceiling; migration requires operator review.'),route_not_live:t('این مسیر در حال اجرا نیست؛ چیزی بازسازی نشد.','This route is not running; nothing was rebuilt.'),config_changed:t('تنظیمات پس از بررسی تغییر کرده‌اند؛ دوباره بررسی کنید.','Configuration changed; inspect again.'),not_idle_healthy:t('مسیر باید سالم و بیکار باشد؛ بعداً دوباره بررسی کنید.','The route must be healthy and idle; inspect again later.'),ownership:t('مالکیت دروازه قابل تأیید نیست؛ تغییری انجام نشد.','Gateway ownership could not be verified; no change was made.'),intent_invalid:t('عملیات ناتمام نیاز به بررسی پشتیبانی دارد.','The pending operation requires support review.'),preflight_unavailable:t('دسترسی امن یا وضعیت دروازه قابل بررسی نیست؛ تغییری انجام نشد.','Secure access or gateway state is unavailable; no change was made.')};
  const friendly=error=>{const key=Object.keys(messages).find(k=>String(error).includes('migration_'+k));return key?messages[key]:error};
  async function call(path,body){try{return await api(path,body)}catch(e){throw Error(friendly(e.message))}}
  async function load(){const selected=target.value,version=++requestGeneration;
   area.replaceChildren(el('p',t('در حال بررسی وضعیت…','Loading migration state…')));
   const base='/api/billing/owner/workspaces/'+selected+'/accounting-migrations',data=await call(base);
   if(version!==requestGeneration||!area.isConnected)return;
   area.replaceChildren();const operations=el('section',undefined,'card');
   if(!data.routes.length)area.append(el('p',t('مسیر ثبت‌شده‌ای وجود ندارد.','There are no registered routes.')));
   for(const route of data.routes){const card=el('article',undefined,'card');add(card,el('h3',t('مسیر ','Route ')+route.id.slice(0,8)),el('p',route.methods.join(' · ')+' · '+route.state));
    const metered=route.accounting==='metered';card.append(el('p',metered?t('حسابداری فعال؛ مهاجرت دوباره لازم نیست.','Accounting enabled; no repeat migration needed.'):route.accounting==='pending'?t('مهاجرت ناتمام؛ با بررسی تازه ادامه دهید.','Pending migration; continue after a fresh inspection.'):t('فاقد حسابداری مشترک','Shared accounting is not enabled.')));
    if(!metered&&route.live)card.append(action(t('پیش‌بررسی و آماده‌سازی','Inspect and prepare'),async()=>{await call(base+'/routes/'+route.id+'/preflight',{});await load()}));
    area.append(card)
   }
   operations.append(el('h3',t('نتیجه و تاریخچه مهاجرت','Migration results and history')));area.append(operations);
   for(const op of data.operations){const card=el('article',undefined,'card'),names={PREPARED:t('پیش‌بررسی موفق؛ آماده اجرا','Preflight passed; ready to execute'),RUNNING:t('مهاجرت در حال اجراست','Migration is running'),PASS:t('مهاجرت موفق','Migration passed'),SUPERSEDED:t('ادامه در عملیات جدید تکمیل شد','Completed by a later recovery operation'),NEEDS_RECOVERY:t('نیاز به بررسی و ادامهٔ امن','Inspection and safe recovery required')};
    add(card,el('h4',t('مسیر ','Route ')+op.route_id.slice(0,8)+' · '+(names[op.state]||op.state)),el('p',op.methods.join(' · ')+' · '+(op.mode||'')+' · '+t('اولویت: ','Pinned member: ')+(op.pin||t('خودکار','Automatic'))));
    if(op.error)card.append(el('p',friendly(op.error),'bad'));
    if(op.state==='PREPARED'){
     const valid=op.expires_at*1000>Date.now()&&data.routes.find(r=>r.id===op.route_id)?.accounting!=='metered';card.append(el('p',t('اعتبار بررسی تا ','Preflight valid until ')+new Date(op.expires_at*1000).toLocaleTimeString()));
     const execute=action(op.resume?t('ادامه با حفظ تنظیمات','Resume preserving settings'):t('مهاجرت با حفظ تنظیمات','Migrate preserving settings'),async()=>{await call(base+'/'+op.id+'/execute',{});await load()},'primary');execute.disabled=!valid;card.append(execute);
     if(!valid)card.append(el('p',data.routes.find(r=>r.id===op.route_id)?.accounting==='metered'?t('این مسیر اکنون حسابداری دارد؛ اجرای دوباره لازم نیست.','This route is already accounted; no repeat execution is needed.'):t('بررسی منقضی شده؛ از کارت مسیر دوباره بررسی کنید.','Preflight expired; inspect the route again.')))
    }
    if(op.state==='PASS'){const r=op.result;add(card,el('p',t('تنظیمات و ورودی حفظ شدند؛ بدون بازسازی تونل‌های زیرین.','Settings and entry retained; no underlying tunnel rebuild.')),el('p',op.controller_backup_verified?t('بکاپ رمزگذاری‌شده کنترلر تأیید شد.','Encrypted controller snapshot verified.'):''));
     if(r.recovered_existing_cutover)card.append(el('p',t('دروازهٔ فعال بدون ری‌استارت دوباره پذیرفته شد.','The running gateway was adopted without another restart.')));
     if(r.maximum_observed_success_gap_s!==null&&r.maximum_observed_success_gap_s!==undefined)card.append(el('p',t('بیشترین فاصلهٔ مشاهده‌شده بین پاسخ‌های موفق: ','Maximum observed gap between successful responses: ')+Number(r.maximum_observed_success_gap_s).toFixed(3)+' s'))
    }
    operations.append(card)
   }
   if(data.operations.some(op=>op.state==='RUNNING'))setTimeout(()=>{if(area.isConnected&&target.value===selected&&version===requestGeneration)run(target,load)},3000)
  }
  target.onchange=()=>run(target,load);chooser.append(action(t('تازه‌سازی وضعیت مهاجرت','Refresh migration status'),load));run(target,load)
 }
 function plansView(){
  const list=el('div',undefined,'admin-list');panel.append(list);
  for(const p of plans){const card=el('article',undefined,'card');add(card,el('h3',p.name),el('p',money(p)+' · '+p.duration_days+t(' روز',' days')+' · '+(p.enabled?'ACTIVE':'DISABLED')),action(t('ویرایش پلن','Edit plan'),async()=>planEditor(p)));list.append(card)}
  const editor=el('div');panel.append(editor);
  function planEditor(p={id:'',name:'',price_minor:'',currency:'IRT',duration_days:30,enabled:true,limits:plans[0]?.limits||{}}){
   editor.replaceChildren();const f=form(editor,p.id?t('ویرایش پلن','Edit plan'):t('تعریف پلن','Create plan'));
   const id=input(f,'id',t('شناسه انگلیسی پلن','Plan ID'),p.id);id.pattern='[a-z][a-z0-9_-]{0,47}';id.readOnly=!!p.id;
   const name=input(f,'name',t('عنوان پلن','Plan name'),p.name);
   const amount=input(f,'price_minor',t('مبلغ در واحد انتخابی؛ IRT یعنی تومان','Price in selected units; IRT means toman'),p.price_minor,'number');amount.max=1000000000000;
   const currency=select(f,'currency',t('واحد پول','Currency'),[['IRT','IRT · تومان'],['IRR','IRR · ریال']],p.currency||'IRT');
   const days=input(f,'duration_days',t('مدت اعتبار؛ روز','Duration in days'),p.duration_days,'number');days.max=366;
   const enabled=check(f,'enabled',t('قابل فروش باشد','Available for sale'),p.enabled);
   const readLimits=limitsForm(f,p.limits,t);
   f.append(el('p',t('ویرایش پلن، سهمیهٔ خریدهای قبلی را تغییر نمی‌دهد؛ خرید یا تمدید بعدی از تنظیم جدید استفاده می‌کند.','Plan edits preserve existing purchases; the next purchase or renewal uses the new terms.'),'muted'));
   submit(f,t('ذخیره پلن','Save plan'),async()=>{await api('/api/billing/owner/plans/'+id.value,{name:name.value,price_minor:Number(amount.value),currency:currency.value,duration_days:Number(days.value),enabled:enabled.checked,limits:readLimits()},'PUT');notify(t('پلن ذخیره شد.','Plan saved.'));await refresh()});
  }
  panel.append(action(t('پلن جدید','New plan'),async()=>planEditor()));
 }
 function paymentsView(){
  const f=form(panel,t('ثبت دریافت مبلغ و فعال‌سازی','Confirm received payment and activate'));
  f.append(el('p',t('این فرم پول جابه‌جا نمی‌کند. فقط پس از اطمینان از دریافت مبلغ، رسید را ثبت کنید. هر شماره مرجع فقط یک بار قابل ثبت است.','This form does not transfer money. Record a receipt only after confirming receipt of funds. Each reference can be used once.'),'note'));
  const workspace=select(f,'workspace_id',t('مشتری','Customer'),workspaces.map(w=>[w.id,w.name]));
  const available=plans.filter(p=>p.enabled&&p.price_minor>0);
  const selected=select(f,'plan',t('پلن','Plan'),available.map(p=>[p.id,p.name+' · '+money(p)]));
  const amount=input(f,'amount_minor',t('مبلغ دریافت‌شده','Amount received'),available[0]?.price_minor||'','number');amount.max=1000000000000;
  const detail=el('p','', 'muted');f.append(detail);
  const update=()=>{const p=available.find(p=>p.id===selected.value);if(p){amount.value=p.price_minor;detail.textContent=p.duration_days+t(' روز · واحد پول: ',' days · currency: ')+p.currency}};selected.onchange=update;update();
  const reference=input(f,'reference',t('شماره مرجع یا رسید پرداخت','Payment reference / receipt'));reference.minLength=3;reference.maxLength=120;
  check(f,'confirmed',t('دریافت این مبلغ را خارج از پنل تأیید می‌کنم','I have confirmed receipt of these funds outside this panel'),false).required=true;
  let requestId=crypto.randomUUID();
  submit(f,t('ثبت پرداخت و فعال‌سازی پلن','Record payment and activate plan'),async()=>{const p=available.find(p=>p.id===selected.value);if(!p)throw Error(t('ابتدا قیمت یک پلن را تعیین کنید.','Configure a priced plan first.'));await api('/api/billing/owner/workspaces/'+workspace.value+'/payments',{request_id:requestId,plan:p.id,amount_minor:Number(amount.value),currency:p.currency,reference:reference.value});requestId=crypto.randomUUID();notify(t('رسید ثبت و دسترسی فعال شد.','Payment recorded and access activated.'));await refresh()});
  if(!available.length)f.append(el('p',t('در بخش پلن‌ها، ابتدا مبلغ و مدت اعتبار را تعیین کنید.','Set a price and duration in Plans first.'),'bad'));
  const list=el('div',undefined,'admin-list');panel.append(list);
  for(const p of payments){const w=workspaces.find(w=>w.id===p.workspace_id),card=el('article',undefined,'card');add(card,el('h3',w?.name||p.workspace_id),el('p',p.amount_minor.toLocaleString()+' '+p.currency+' · '+p.plan),el('p',t('مرجع: ','Reference: ')+p.reference),el('p',t('اعتبار تا: ','Access until: ')+new Date(p.paid_through*1000).toLocaleString()));list.append(card)}
  if(requests.length){list.append(el('h3',t('درخواست‌های مشتریان','Customer requests')));for(const request of requests)list.append(el('p',(workspaces.find(w=>w.id===request.workspace_id)?.name||request.workspace_id)+' · '+request.plan+' · '+request.state))}
 }
 switchTo(active);
}};
})();
